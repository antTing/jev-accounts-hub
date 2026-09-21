package outproxy

import "testing"

func TestParseURLAndHostPort(t *testing.T) {
	p, err := Parse("http://user:pass@proxy.example.com:8080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "http" || p.Host != "proxy.example.com" || p.Port != 8080 || p.Username != "user" || p.Password != "pass" {
		t.Fatalf("%+v", p)
	}

	p, err = Parse("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "socks5h" {
		t.Fatalf("want socks5h got %s", p.Protocol)
	}

	p, err = Parse("1.2.3.4:3128")
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "http" || p.Host != "1.2.3.4" || p.Port != 3128 {
		t.Fatalf("%+v", p)
	}

	p, err = Parse("1.2.3.4:3128:alice:s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if p.Username != "alice" || p.Password != "s3cret" {
		t.Fatalf("%+v", p)
	}

	p, err = Parse("alice:s3cret@1.2.3.4:3128")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "1.2.3.4" || p.Username != "alice" {
		t.Fatalf("%+v", p)
	}

	if _, err := Parse(""); err == nil {
		t.Fatal("empty should fail")
	}
	if _, err := Parse("ftp://x:1"); err == nil {
		t.Fatal("ftp should fail")
	}
}

func TestParseLineNamed(t *testing.T) {
	p, err := ParseLine("us-east socks5://10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "us-east" || p.Protocol != "socks5h" || p.Host != "10.0.0.1" {
		t.Fatalf("%+v", p)
	}
	if _, err := ParseLine("# comment"); err == nil {
		t.Fatal("comment")
	}
}

func TestURLRoundTrip(t *testing.T) {
	p, err := Parse("http://first last@corp:p@ ss:#word@proxy.example.com:3128")
	if err != nil {
		// url.Parse may reject the unencoded form; encoded form must work
		p, err = Parse("http://first%20last%40corp:p%40%20ss%3A%23word@proxy.example.com:3128")
		if err != nil {
			t.Fatal(err)
		}
	}
	got := URL(p)
	back, err := Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if back.Host != "proxy.example.com" || back.Port != 3128 || back.Username == "" {
		t.Fatalf("roundtrip %+v url %s", back, got)
	}
}
