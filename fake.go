package main

import (
	"crypto/sha1"
	"fmt"
	"math/rand"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/go-openapi/swag"
	"gopkg.in/yaml.v3"

	"github.com/SecurityBrewery/catalyst/database/migrations"
	"github.com/SecurityBrewery/catalyst/generated/model"
	"github.com/SecurityBrewery/catalyst/generated/pointer"
)

func fakeArtifacts() []*model.Artifact {
	var artifacts []*model.Artifact

	artifactCount := gofakeit.Number(0, 10)

	for i := 0; i < artifactCount; i++ {
		artifacts = append(artifacts, fakeArtifact())
	}

	return artifacts
}

func fakeArtifact() *model.Artifact {
	var artifactNames []string
	artifactNames = append(artifactNames, gofakeit.URL())
	artifactNames = append(artifactNames, gofakeit.DomainName())
	artifactNames = append(artifactNames, gofakeit.IPv4Address())
	artifactNames = append(artifactNames, fmt.Sprintf("%x", sha1.Sum([]byte(gofakeit.Word()))))

	status := gofakeit.RandomString([]string{"unknown", "malicious", "clean"})

	return &model.Artifact{Name: gofakeit.RandomString(artifactNames), Status: &status}
}

func fakeReferences() []*model.Reference {
	return []*model.Reference{
		{Name: gofakeit.Word(), Href: gofakeit.URL()},
		{Name: gofakeit.Word(), Href: gofakeit.URL()},
		{Name: gofakeit.Word(), Href: gofakeit.URL()},
	}
}

func fakePlaybookTemplates() []*model.PlaybookTemplateForm {
	return []*model.PlaybookTemplateForm{
		fakePlaybookTemplate(migrations.MalwarePlaybook),
		fakePlaybookTemplate(migrations.PhishingPlaybook),
	}
}

func fakePlaybookTemplate(playbookString string) *model.PlaybookTemplateForm {
	playbookTemplate := &model.Playbook{}
	err := yaml.Unmarshal([]byte(playbookString), playbookTemplate)
	if err != nil {
		panic(err)
	}

	return &model.PlaybookTemplateForm{Yaml: playbookString}
}

func fakeAlert() *model.TicketForm {
	fakeAlertGens := []func() *model.TicketForm{fakeLeak, fakeMalwareAlert, fakePhishingAlert}
	gofakeit.ShuffleAnySlice(fakeAlertGens)
	return fakeAlertGens[0]()
}

func fakeLeak() *model.TicketForm {
	company := gofakeit.Company()

	title := gofakeit.RandomString([]string{
		fmt.Sprintf("Credential leak at %s", company),
		fmt.Sprintf("%s public credentials", company),
	})

	leaked := ""
	for i := 0; i < rand.Intn(100); i++ {
		leaked += gofakeit.RandomString([]string{
			gofakeit.Username(),
			gofakeit.Email(),
			gofakeit.Password(true, true, true, true, false, 8),
		})
		leaked += "\n"
	}

	return &model.TicketForm{
		Type:       "alert",
		Details:    map[string]interface{}{"Status": "New"},
		References: fakeReferences(),
		Name:       title,
		Status:     fakeStatus(),
		Created:    swag.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
	}
}

func fakeMalwareAlert() *model.TicketForm {
	title := fmt.Sprintf("%s %s detected", gofakeit.AppName(), gofakeit.RandomString([]string{
		"virus", "worm", "trojan",
	}))

	return &model.TicketForm{
		Type:       "alert",
		References: fakeReferences(),
		Name:       title,
		Status:     fakeStatus(),
		Created:    swag.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
	}
}

func fakePhishingAlert() *model.TicketForm {
	title := gofakeit.RandomString([]string{
		fmt.Sprintf("phishing from %s detected", gofakeit.Email()),
		fmt.Sprintf("phishing campaing related to %s %s", gofakeit.Adjective(), gofakeit.Animal()),
	})

	return &model.TicketForm{
		Type:       "alert",
		References: fakeReferences(),
		Owner:      fakeHandler(),
		Name:       title,
		Status:     fakeStatus(),
		Created:    swag.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
	}
}

func fakeStatus() string {
	status := "open"
	if gofakeit.Number(0, 99) != 0 {
		status = "closed"
	}
	return status
}

func fakeHandler() *string {
	user := gofakeit.RandomString([]string{"alice", "bob", "carol", "dave", "eve", "nil"})
	if user == "nil" {
		return nil
	}
	return swag.String(user)
}

func fakeIncident() *model.TicketForm {
	playbookTemplates := fakePlaybookTemplates()
	gofakeit.ShuffleAnySlice(playbookTemplates)

	return &model.TicketForm{
		Details:    map[string]interface{}{},
		Name:       gofakeit.Adjective() + " " + gofakeit.Animal(),
		Owner:      fakeHandler(),
		Playbooks:  []*model.PlaybookTemplateForm{playbookTemplates[0]},
		References: fakeReferences(),
		Schema:     pointer.String(migrations.DefaultTemplateSchema),
		Status:     fakeStatus(),
		Type:       "incident",
		Created:    pointer.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
	}
}

func fakeCustomTicketInvestigation() *model.TicketForm {
	playbookTemplates := fakePlaybookTemplates()
	gofakeit.ShuffleAnySlice(playbookTemplates)

	return &model.TicketForm{
		Type:       "investigation",
		Details:    map[string]interface{}{},
		Playbooks:  []*model.PlaybookTemplateForm{playbookTemplates[0]},
		References: fakeReferences(),
		Schema:     pointer.String(migrations.DefaultTemplateSchema),
		Name:       gofakeit.Adjective() + " " + gofakeit.Animal(),
		Status:     fakeStatus(),
		Owner:      fakeHandler(),
		Created:    pointer.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
	}
}

func fakeCustomTicketHunt() *model.TicketForm {
	playbookTemplates := fakePlaybookTemplates()
	gofakeit.ShuffleAnySlice(playbookTemplates)

	return &model.TicketForm{
		Type:       "hunt",
		Details:    map[string]interface{}{},
		Playbooks:  []*model.PlaybookTemplateForm{playbookTemplates[0]},
		References: fakeReferences(),
		Schema:     swag.String(migrations.DefaultTemplateSchema),
		Name:       gofakeit.Adjective() + " " + gofakeit.Animal(),
		Status:     fakeStatus(),
		Owner:      fakeHandler(),
		Created:    swag.Time(gofakeit.DateRange(time.Now().Add(-time.Hour*24*356), time.Now())),
		Artifacts:  fakeArtifacts(),
	}
}
