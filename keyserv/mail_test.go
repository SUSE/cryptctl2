// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package keyserv

import (
	"net"
	"testing"
)

func TestMailerValidateConfig(t *testing.T) {
	m := Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	m = Mailer{Recipients: []string{"a@b"}, FromAddress: "me@a", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err != nil {
		t.Fatal(err)
	}
	m = Mailer{Recipients: []string{}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "", AgentAddressPort: "a.example:25"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25a"}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
	m = Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: ""}
	if err := m.ValidateConfig(); err == nil {
		t.Fatal("did not error")
	}
}

func TestMailerSend(t *testing.T) {
	m := Mailer{Recipients: []string{"a@b.c"}, FromAddress: "me@a.example", AgentAddressPort: "a.example:25"}
	if err := m.Send("abc", "123"); err == nil {
		t.Fatal("did not error")
	}
	if _, err := net.Dial("tcp", "localhost:25"); err != nil {
		t.Skip("an MTA on localhost would be required to continue this test")
	}
	m = Mailer{Recipients: []string{"root@localhost"}, FromAddress: "root@localhost", AgentAddressPort: "localhost:25"}
	if err := m.Send("cryptctl2 mailer test subject", "cryptctl2 mailer test text body"); err != nil {
		t.Fatal(err)
	}
}

func TestMailerReadFromSysconfig(t *testing.T) {
	m := Mailer{}
	mailConf := GetDefaultKeySvcConf()
	m.ReadFromSysconfig(mailConf)
	if len(m.Recipients) != 0 || m.FromAddress != "" || m.AgentAddressPort != "" {
		t.Fatal(m)
	}
	mailConf.SetStrArray("EMAIL_RECIPIENTS", []string{"a", "b"})
	mailConf.Set("EMAIL_FROM_ADDRESS", "c")
	mailConf.Set("EMAIL_AGENT_AND_PORT", "d")
	m.ReadFromSysconfig(mailConf)
	if len(m.Recipients) != 2 || m.FromAddress != "c" || m.AgentAddressPort != "d" {
		t.Fatal(m)
	}
}
