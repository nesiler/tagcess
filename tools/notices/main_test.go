package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "MIT",
			text: `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.`,
			want: []string{"MIT"},
		},
		{
			name: "MIT with the copyright above the title (go-humanize)",
			text: `Copyright (c) 2005-2008 Dustin Sallings

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.`,
			want: []string{"MIT"},
		},
		{
			name: "BSD-3-Clause",
			text: `Copyright 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright notice, this list
     of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright notice.
   * Neither the name of Google LLC nor the names of its contributors may be used to
     endorse or promote products derived from this software.`,
			want: []string{"BSD-3-Clause"},
		},
		{
			name: "BSD-2-Clause",
			text: `Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.`,
			want: []string{"BSD-2-Clause"},
		},
		{
			name: "Apache-2.0",
			text: `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION`,
			want: []string{"Apache-2.0"},
		},
		{
			name: "ISC",
			text: `ISC License

Permission to use, copy, modify, and/or distribute this software for any purpose with
or without fee is hereby granted, provided that the above copyright notice and this
permission notice appear in all copies.`,
			want: []string{"ISC"},
		},
		{
			name: "0BSD",
			text: `BSD Zero Clause License

Copyright (c) 2020 Big Sky Software, Inc.

Permission to use, copy, modify, and/or distribute this software for any purpose with
or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES.`,
			want: []string{"0BSD"},
		},
		{
			name: "Unlicense",
			text: `This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary.`,
			want: []string{"Unlicense"},
		},
		{
			name: "OFL-1.1",
			text: `SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide development.`,
			want: []string{"OFL-1.1"},
		},
		{
			name: "dual MIT and Apache (go.yaml.in/yaml/v3)",
			text: `This project is covered by two different licenses: MIT and Apache.

#### MIT License ####

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software").

THE SOFTWARE IS PROVIDED "AS IS".

### Apache License ###

Licensed under the Apache License, Version 2.0 (the "License");`,
			want: []string{"Apache-2.0", "MIT"},
		},
		{
			name: "Apache text with an appended BSD-3 part (go.opentelemetry.io/otel)",
			text: `                                 Apache License
                           Version 2.0, January 2004

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

--------------------------------------------------------------------------------

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   * Redistributions of source code must retain the above copyright notice.
   * Neither the name of Google LLC nor the names of its contributors may be used.`,
			want: []string{"Apache-2.0", "BSD-3-Clause"},
		},
		{
			name: "GPL-3.0 is not recognised",
			text: `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007`,
			want: nil,
		},
		{
			name: "no licence text",
			text: "Copyright 2026 Example. All rights reserved.",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.text)
			if strings.Join(got, ", ") != strings.Join(tt.want, ", ") {
				t.Errorf("classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAllowedLicences pins the allowlist to the developer's decision of 2026-10-15.
func TestAllowedLicences(t *testing.T) {
	want := "0BSD,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MIT,OFL-1.1,Unlicense"
	if got := strings.Join(displayAllowlist(), ","); got != want {
		t.Errorf("allowlist = %q, want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		licence string
		ok      bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"Apache-2.0, BSD-3-Clause", true},
		{"0BSD", true},
		{"GPL-3.0", false},
		{"MIT, GPL-3.0", false},
		{"", false},
	}
	for _, tt := range tests {
		err := validate([]component{{name: "example.com/dep", licence: tt.licence}})
		if tt.ok && err != nil {
			t.Errorf("validate(%q) = %v, want nil", tt.licence, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("validate(%q) = nil, want an error", tt.licence)
		}
	}
}

func TestLicenceFile(t *testing.T) {
	root := t.TempDir()
	write := func(root, rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("root licence wins over a nested one", func(t *testing.T) {
		write(root, "LICENSE", "root")
		write(root, "sub/LICENSE", "nested")
		got, err := licenceFile(root)
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(root, "LICENSE") {
			t.Errorf("licenceFile() = %s, want the root LICENSE", got)
		}
	})

	t.Run("COPYING is accepted", func(t *testing.T) {
		dir := t.TempDir()
		write(dir, "COPYING", "copying")
		got, err := licenceFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != filepath.Join(dir, "COPYING") {
			t.Errorf("licenceFile() = %s, want COPYING", got)
		}
	})

	t.Run("a suffixed file is not a licence file", func(t *testing.T) {
		dir := t.TempDir()
		write(dir, "LICENSE-3RD-PARTY.md", "third party")
		if _, err := licenceFile(dir); err == nil {
			t.Error("licenceFile() accepted LICENSE-3RD-PARTY.md; want an error")
		}
	})
}

// TestGenerateMatchesCommitted is AC1's local test: THIRD_PARTY_NOTICES must be the exact
// output of the generator, so a dependency change without regenerating it fails here too.
func TestGenerateMatchesCommitted(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	content, err := generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(root, noticesFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(committed) {
		t.Errorf("%s is out of date; run `make notices` and commit the result", noticesFile)
	}
}

// TestGenerateIgnoresHostTarget is the regression test for the macOS/Linux mismatch: the
// generator pins GOOS/GOARCH, so setting a different host target must not change the output.
func TestGenerateIgnoresHostTarget(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	want, err := generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOS", "darwin")
	t.Setenv("GOARCH", "arm64")
	t.Setenv("CGO_ENABLED", "1")
	got, err := generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Error("generate() output depends on the host GOOS/GOARCH; pin the shipping target")
	}
}

func TestGenerateListsShippedComponents(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	content, err := generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"github.com/a-h/templ",     // direct dependency
		"modernc.org/sqlite",       // indirect dependency
		"htmx",                     // embedded JS library
		"@codemirror/view",         // editor bundle dependency
		"go.opentelemetry.io/otel", // module with two licence files
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("%s does not list %s", noticesFile, want)
		}
	}
	// The `go tool` dependencies do not ship in a binary, so they must not be listed.
	if strings.Contains(string(content), "github.com/sqlc-dev/sqlc") {
		t.Errorf("%s lists sqlc, which is a build tool and does not ship", noticesFile)
	}
}
