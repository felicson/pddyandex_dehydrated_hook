package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type PriorityValue int64
type DNSRecords []DNSRecord

type DNSRecord struct {
	Record_id int64
	Type      string
	Content   string
	Domain    string
	FQDN      string
	Priority  PriorityValue
	TTL       int64
	Subdomain string
}

type ListDNSRecordsResponse struct {
	Records DNSRecords
	Success string
	Error   string
}

type CreateDNSRecordResponce struct {
	Record  DNSRecord
	Success string
	Error   string
}
type DeleteDNSRecordResponce struct {
	DNSRecord
	Success string
	Error   string
}

const (
	apiURL = "https://pddimp.yandex.ru"
)

func (p *PriorityValue) UnmarshalJSON(b []byte) (err error) {
	s, n := "foobar", uint64(0)
	if err = json.Unmarshal(b, &s); err == nil {
		*p = 0
		return nil
	}

	if err = json.Unmarshal(b, &n); err == nil {
		_ = "breakpoint"
		*p = PriorityValue(n)
	}
	return nil
}

func PrintRecords(records []DNSRecord) {
	fmt.Printf("ID\t\tType\t\tSubdomain\tContent\n")
	fmt.Printf("--------\t-----\t\t--------\t-------\n")

	for _, record := range records {
		fmt.Printf(
			"%-12d\t%-12s\t%-12s\t%-12s\n",
			record.Record_id,
			record.Type,
			record.Subdomain,
			record.Content,
		)
	}
}

func DeleteAcmeRecord(pddToken string, domain string, txtChallenge string) error {

	dnsRecords, err := retrieveDomainRecords(pddToken, domain)
	if err != nil {
		panic(err)
	}
	filteredRecords := FilterRecordsByTxtChallenge(dnsRecords, []string{txtChallenge})
	if len(filteredRecords) < 1 {
		return errors.New("Acme dns record with content " + txtChallenge + " - not found")
	}
	client := &http.Client{}
	req, _ := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api2/admin/dns/del", apiURL),
		nil)
	req.Header.Set("PddToken", pddToken)

	values := req.URL.Query()
	values.Add("domain", domain)
	values.Add("record_id", fmt.Sprintf("%d", filteredRecords[0].Record_id))
	req.URL.RawQuery = values.Encode()

	resp, err := client.Do(req)

	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	var container DeleteDNSRecordResponce
	err = json.Unmarshal(body, &container)

	if err != nil {
		return err
	}
	if container.Success == "error" {
		return errors.New(container.Error)
	}

	return nil
}
func CreateAcmeRecord(pddToken string, domain string, txtChallenge string) ([]DNSRecord, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/api2/admin/dns/add", apiURL),
		nil)
	req.Header.Set("PddToken", pddToken)

	values := req.URL.Query()
	values.Add("domain", domain)
	values.Add("type", "TXT")
	values.Add("content", txtChallenge)
	values.Add("ttl", "3600")
	values.Add("subdomain", fmt.Sprintf("_acme-challenge.%s", domain))
	req.URL.RawQuery = values.Encode()

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	var container CreateDNSRecordResponce
	err = json.Unmarshal(body, &container)

	if err != nil {
		return nil, err
	}
	if container.Success == "error" {
		return nil, errors.New(container.Error)
	}

	return []DNSRecord{container.Record}, nil
}

func retrieveDomainRecords(pddToken string, domain string) ([]DNSRecord, error) {
	client := &http.Client{}
	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/api2/admin/dns/list", apiURL),
		nil)
	req.Header.Set("PddToken", pddToken)

	values := req.URL.Query()
	values.Add("domain", domain)
	req.URL.RawQuery = values.Encode()

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	var container ListDNSRecordsResponse
	err = json.Unmarshal(body, &container)

	if err != nil {
		return nil, err
	}

	return container.Records, nil
}

func Contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func FilterRecordsByTxtChallenge(records []DNSRecord, challenge []string) []DNSRecord {

	var approved_records []DNSRecord

	for _, r := range records {
		if Contains(r.Content, challenge) {
			approved_records = append(approved_records, r)
		}
	}
	return approved_records
}

func main() {

	pddToken := os.Getenv("PDD_TOKEN")

	if pddToken == "" {
		fmt.Println("Require PDD_TOKEN env variable for api auth")
		os.Exit(1)
	}
	allowedHooks := []string{"deploy_challenge", "clean_challenge"}

	hook_stage := os.Args[1]
	if !Contains(hook_stage, allowedHooks) {
		return
	}
	domain := os.Args[2]
	txtChallenge := os.Args[4]

	var dnsRecords []DNSRecord
	var err error

	fmt.Println(hook_stage)
	fmt.Println(domain)

	fmt.Printf("Stage\t\t\tDomain\t\t\tChallenge\n")
	fmt.Printf("--------\t\t-----\t\t\t--------\n")

	fmt.Printf(
		"%-12s\t%-12s\t\t%-12s\n",
		hook_stage,
		domain,
		txtChallenge,
	)

	if hook_stage == "deploy_challenge" {
		dnsRecords, err = CreateAcmeRecord(pddToken, domain, txtChallenge)
		if err != nil {
			panic(err)
		}
		PrintRecords(dnsRecords)
	} else if hook_stage == "clean_challenge" {

		err = DeleteAcmeRecord(pddToken, domain, txtChallenge)
		if err != nil {
			panic(err)
		}
	}

}
