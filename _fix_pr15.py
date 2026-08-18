"""Fix 1 (branch fix/redact-credentials): a assercao que o CodeQL flagra."""
import hashlib, io

p = "tests/test_redact.py"
s = io.open(p, encoding="utf-8").read()

s = s.replace('TOKEN = "s3cr3t-production-token-value"',
              'TOKEN = "s3cr3t-production-token-value"\nURL = "https://app.example.com"', 1)
s = s.replace('    return Target(type=TargetType.WEB, url="https://app.example.com",',
              '    return Target(type=TargetType.WEB, url=URL,', 1)

old = '''    argv = ["nuclei", "-u", "https://app.example.com",
            "-H", f"Authorization: Bearer {TOKEN}", "-jsonl"]
    out = redact_argv(argv, [TOKEN])
    assert TOKEN not in out
    # "this ran authenticated" is worth keeping in a report
    assert "Authorization" in out and MASK in out
    # membership in the *parsed* argv, not a substring of the whole line: that
    # is what shlex.quote is supposed to guarantee, and a substring check
    # against a URL is the classic incomplete-sanitization pattern
    assert "https://app.example.com" in shlex.split(out)'''
new = '''    argv = ["nuclei", "-u", URL, "-H", f"Authorization: Bearer {TOKEN}", "-jsonl"]
    out = redact_argv(argv, [TOKEN])
    assert TOKEN not in out
    # Compare the whole parsed argv, element by element. This pins exactly what
    # changed and what did not — including that the URL survives as ONE
    # argument, which is the point of shlex.quote — and it avoids asserting a
    # substring against a URL, which is the shape of an incomplete host check.
    assert shlex.split(out) == [
        "nuclei", "-u", URL, "-H", f"Authorization: {MASK}", "-jsonl"]'''
assert s.count(old) == 1, "assercao antiga nao encontrada"
s = s.replace(old, new, 1)
io.open(p, "w", encoding="utf-8").write(s)

got = hashlib.sha256(open(p, "rb").read()).hexdigest()
want = "0f4b0a2c"          # so os primeiros bytes sao verificados no fix 2
print("tests/test_redact.py atualizado (sha256", got[:16] + "...)")
