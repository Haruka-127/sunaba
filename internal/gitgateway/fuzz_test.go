package gitgateway

import "testing"

func FuzzCanonicalPushBinding(f *testing.F) {
	validOld := "1111111111111111111111111111111111111111"
	validNew := "2222222222222222222222222222222222222222"
	f.Add("https://example.com/repo.git", "refs/heads/main", validOld, validNew, "repository")
	f.Add("https://user@example.com/repo.git", "refs/heads/main", validOld, validNew, "repository")
	f.Add("https://example.com/repo.git\n", "refs/heads/main\n", validOld, validNew, "../repository")
	f.Fuzz(func(t *testing.T, remote, ref, oldObject, newObject, repository string) {
		if len(remote)+len(ref)+len(oldObject)+len(newObject)+len(repository) > 16<<10 {
			t.Skip()
		}
		binding := PushBinding{
			ProjectID: "project", Repository: repository, RemoteName: "origin", RemoteURL: remote,
			Updates: []RefUpdate{{Ref: ref, Old: oldObject, New: newObject}},
		}
		canonical, digest, err := canonicalBinding(binding)
		if err != nil {
			return
		}
		repeated, repeatedDigest, err := canonicalBinding(canonical)
		if err != nil || digest != repeatedDigest || len(digest) != 64 || repeated.RemoteURL != canonical.RemoteURL {
			t.Fatalf("canonical push binding is not stable: digest=%q repeated=%q error=%v", digest, repeatedDigest, err)
		}
		if containsControl(canonical.RemoteURL + canonical.Updates[0].Ref + canonical.Repository) {
			t.Fatal("canonical binding retained control characters")
		}
	})
}
