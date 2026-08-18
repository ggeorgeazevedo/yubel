"""Fix 2 (branch refactor/engine-contract): tira o parametro extra do NOME do
contrato. Rodar DEPOIS de mergear fix/redact-credentials nesta branch."""
import hashlib, io

rd = lambda p: io.open(p, encoding="utf-8").read()
wr = lambda p, s: io.open(p, "w", encoding="utf-8").write(s)

def sub(p, old, new, n=1):
    s = rd(p); assert s.count(old) == n, (p, s.count(old), old[:60])
    wr(p, s.replace(old, new, n))

# ---- nuclei: build_command_for / parse_for ---------------------------------
p = "src/yubel/engines/nuclei.py"
sub(p, "            cmd = self.build_command(target, workdir, dast)",
       "            cmd = self.build_command_for(target, workdir, dast)")
sub(p, "            fs = self.parse(target, workdir, proc.stdout, dast)",
       "            fs = self.parse_for(target, workdir, proc.stdout, dast)")
sub(p, "    def build_command(self, target: Target, workdir: str, dast: bool = False) -> List[str]:",
'''    def build_command(self, target: Target, workdir: str) -> List[str]:
        """The base contract: the full-template pass."""
        return self.build_command_for(target, workdir, dast=False)

    def build_command_for(self, target: Target, workdir: str,
                          dast: bool = False) -> List[str]:''')
sub(p, '''    def parse(self, target: Target, workdir: str, stdout: str,
              dast: bool = False) -> List[Finding]:''',
'''    def parse(self, target: Target, workdir: str, stdout: str) -> List[Finding]:
        """The base contract: the full-template pass."""
        return self.parse_for(target, workdir, stdout, dast=False)

    def parse_for(self, target: Target, workdir: str, stdout: str,
                  dast: bool = False) -> List[Finding]:''')

# ---- dalfox: build_command_for ---------------------------------------------
p = "src/yubel/engines/dalfox.py"
sub(p, "            cmd = self.build_command(target, workdir, url)",
       "            cmd = self.build_command_for(target, workdir, url)")
sub(p, '''    def build_command(self, target: Target, workdir: str,
                      url: str = None) -> List[str]:''',
'''    def build_command(self, target: Target, workdir: str) -> List[str]:
        """The base contract: the target's own endpoint."""
        return self.build_command_for(target, workdir)

    def build_command_for(self, target: Target, workdir: str,
                          url: str = None) -> List[str]:''')

# ---- call sites nos testes existentes --------------------------------------
for p, pairs in {
    "tests/test_crawl.py": [
        ('NucleiEngine().build_command(_web(), "/tmp", dast=False)',
         'NucleiEngine().build_command_for(_web(), "/tmp", dast=False)'),
        ('NucleiEngine().build_command(t, str(tmp_path), dast=False)',
         'NucleiEngine().build_command_for(t, str(tmp_path), dast=False)'),
        ('NucleiEngine().build_command(t, str(tmp_path), dast=True)',
         'NucleiEngine().build_command_for(t, str(tmp_path), dast=True)'),
        ('DalfoxEngine().build_command(_web(), "/tmp", url="http://t.example/x?id=1")',
         'DalfoxEngine().build_command_for(_web(), "/tmp", url="http://t.example/x?id=1")'),
    ],
    "tests/test_engines.py": [
        ('eng.build_command(_web(), "/tmp", dast=False)',
         'eng.build_command_for(_web(), "/tmp", dast=False)'),
        ('eng.build_command(_web(), "/tmp", dast=True)',
         'eng.build_command_for(_web(), "/tmp", dast=True)'),
        ('NucleiEngine(cfg.options["nuclei"]).build_command(',
         'NucleiEngine(cfg.options["nuclei"]).build_command_for('),
    ],
    "tests/test_redact.py": [
        ('("nuclei", NucleiEngine().build_command(target, str(tmp_path), False)),',
         '("nuclei", NucleiEngine().build_command(target, str(tmp_path))),'),
    ],
}.items():
    for old, new in pairs:
        sub(p, old, new)

# ---- o teste de contrato passa a checar o desenho novo ----------------------
sub("tests/test_engine_contract.py",
'''def test_widening_with_optional_parameters_is_allowed():
    """nuclei and dalfox legitimately take an extra argument from their own
    `run()`. That is fine precisely because it is optional — the base contract
    still holds."""
    from yubel.engines.dalfox import DalfoxEngine
    from yubel.engines.nuclei import NucleiEngine

    assert _accepts(NucleiEngine().build_command, 3)   # ... + dast
    assert _accepts(NucleiEngine().build_command, 2)   # ... and without it
    assert _accepts(DalfoxEngine().build_command, 3)   # ... + url
    assert _accepts(DalfoxEngine().build_command, 2)''',
'''def test_extra_parameters_live_on_their_own_method():
    """nuclei needs a `dast` flag and dalfox a `url`, both driven from their
    own `run()`. Those go on a separate method rather than widening the
    contract name: a call passing a third argument to `build_command` is what
    made the base signature disagree with its use in the first place."""
    from yubel.engines.dalfox import DalfoxEngine
    from yubel.engines.nuclei import NucleiEngine

    for engine, extra in ((NucleiEngine(), "build_command_for"),
                          (DalfoxEngine(), "build_command_for")):
        assert _accepts(getattr(engine, extra), 3)
        # and the contract name stays exactly two positional arguments
        assert _accepts(engine.build_command, 2)
        assert not _accepts(engine.build_command, 3)''')

exp = {
 "tests/test_redact.py":          "63c66f465e620e627b43e63b7a42f8f9c02b8ed67871c781ffe5f97d6ef51249",
 "src/yubel/engines/nuclei.py":   "bc93a886268a6f0a031404bdbf203a848403ce7cb5082f0a9ce55c6a9b8c59d4",
 "src/yubel/engines/dalfox.py":   "16ac8b46527e67f0fa039ef6e168f17c26c059ddd936fe9a4e842b8cdebaed91",
 "tests/test_crawl.py":           "c357b8617d2233dc558d775f0f4746560d16492fbec29aee99821c20453af3a3",
 "tests/test_engines.py":         "9fa98906a7fdf3db52bebb13bfdd95e2d7a141e0165cf6f8db48a5e976444d28",
 "tests/test_engine_contract.py": "7d2b0c77d44bb27a3429f73b63a48469ba570a96e5bcc30f75878b820cfbd423",
}
bad = 0
for p, want in exp.items():
    got = hashlib.sha256(open(p, "rb").read()).hexdigest()
    bad += got != want
    print(("OK   " if got == want else "DIFF ") + p)
print("\nTUDO IDENTICO AO VALIDADO COM CODEQL:", bad == 0)
