from hash_identifier.main import main

def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "1.0.0" in capsys.readouterr().out

def test_cli_json_no_history(capsys, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert main(["identify", "a"*64, "--json", "--no-history"]) == 0
    assert '"confidence"' in capsys.readouterr().out
