package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/SecurityBrewery/catalyst/generated/model"
	"github.com/SecurityBrewery/catalyst/generated/pointer"
	"github.com/SecurityBrewery/catalyst/role"
)

func main() {
	log.SetFlags(log.Llongfile | log.LstdFlags)

	if len(os.Args) != 3 {
		log.Fatalln("usage: faker <url> <key>")
	}

	g := &Generator{
		url: os.Args[1],
		key: os.Args[2],
	}

	log.Println("generate dummy data", g.url, len(g.key))

	if err := g.userDummyData(); err != nil {
		log.Fatal(err)
	}
	if err := g.ticketDummyData(); err != nil {
		log.Fatal(err)
	}
	if err := g.dashboardDummyData(); err != nil {
		log.Fatal(err)
	}
}

type Generator struct {
	url string
	key string
}

var analyst = role.Strings([]role.Role{
	role.AutomationRead, role.CurrentuserdataRead, role.CurrentuserdataWrite,
	role.CurrentuserRead, role.GroupRead, role.PlaybookRead, role.RuleRead,
	role.SettingsRead, role.TemplateRead, role.TicketRead, role.TicketWrite,
	role.TickettypeRead, role.UserRead, role.DashboardRead,
})

var users = []*model.UserForm{
	{ID: "alice", Blocked: false, Roles: analyst},
	{ID: "bob", Blocked: false, Roles: analyst},
	{ID: "carol", Blocked: false, Roles: analyst},
	{ID: "dave", Blocked: false, Roles: analyst},

	{ID: "eve", Blocked: false, Roles: []string{role.Admin}},
}

// var settings = []*models.Setting{
// 	{Email: swag.String("alice@example.com"), Name: swag.String("Alice Alert Analyst"),, : "alice"},
// 	{Email: swag.String("bob@example.com"), Name: swag.String("Bob Incident Handler"), Username: "bob"},
// 	{Email: swag.String("carol@example.com"), Name: swag.String("Carol Forensicator"), Username: "carol"},
// 	{Email: swag.String("dave@example.com"), Name: swag.String("Dave Admin"), Username: "dave"},
// 	{Email: swag.String("eve@example.com"), Name: swag.String("Eve Team Lead"), Username: "eve"},
// }

func (g *Generator) dashboardDummyData() error {
	simple := &model.Dashboard{
		Name: "Simple",
		Widgets: []*model.Widget{
			{
				Aggregation: "type",
				Filter:      pointer.String("status == 'open'"),
				Name:        "Types",
				Type:        "pie",
				Width:       8,
			},
			{
				Aggregation: "owner",
				Filter:      pointer.String("status == 'open'"),
				Name:        "Owners",
				Type:        "bar",
				Width:       4,
			},
		},
	}

	log.Println("create dashboard")
	return postJSON(simple, g.url+"/dashboards", g.key)
}

func (g *Generator) userDummyData() error {
	for _, user := range users {
		log.Println("create user ", user.ID)
		_ = postJSON(user, g.url+"/users", g.key)
	}
	return nil
}

func (g *Generator) ticketDummyData() error {
	if err := g.createTickets(10_000, fakeIncident); err != nil {
		return err
	}
	if err := g.createTickets(200_000, fakeAlert); err != nil {
		return err
	}
	if err := g.createTickets(100, fakeCustomTicketInvestigation); err != nil {
		return err
	}
	if err := g.createTickets(240, fakeCustomTicketHunt); err != nil {
		return err
	}

	return nil
}

func (g *Generator) createTickets(count int, createFunc func() *model.TicketForm) error {
	log.Println("create ticket")
	var tickets []*model.TicketForm
	for j := 0; j < count; j++ {
		tickets = append(tickets, createFunc())

		if len(tickets) > 100 {
			if err := postJSON(tickets, g.url+"/tickets/batch", g.key); err != nil {
				return err
			}
			tickets = nil
		}
	}
	if len(tickets) > 0 {
		if err := postJSON(tickets, g.url+"/tickets/batch", g.key); err != nil {
			return err
		}
	}
	return nil
}

func postJSON(data interface{}, url, key string) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Set("PRIVATE-TOKEN", key)
	req.Header.Set("Content-Type", "application/json")
	req.Close = true

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 204 {
		b, _ := io.ReadAll(resp.Body)
		return errors.New(string(b))
	}

	return nil
}
