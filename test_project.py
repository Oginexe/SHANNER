from project import is_valid_dump, offline_check, read_dump_date, read_hash


def test_read_hash():
    assert read_hash("") == set()
    assert read_hash("# comments\n\n") == set()
    assert read_hash("abcd\nefg\n") == {"abcd", "efg"}
    assert read_hash(" abc \r\nabc\n") == {"abc"}


def test_read_dump_date():
    assert (
        read_dump_date("# title\n# Last updated: 2026-11-09 13:38:03 UTC\nabc\n")
        == "2026-11-09 13:38:03 UTC"
    )
    assert (
        read_dump_date(
            "# Last updated: 2026-11-09 13:38:03 UTC                        #\n"
        )
        == "2026-11-09 13:38:03 UTC"
    )
    assert read_dump_date("") == None
    assert read_dump_date("def\n") == None


def test_offline_check():
    assert (
        offline_check("aaaa", {"aaaa", "bbb"})
        == "WARNING: Hash found in local database!"
    )
    assert (
        offline_check("zzz", {"aaa", "bbb"})
        == "Hash not found in local database. This does not mean it's safe."
    )
    assert (
        offline_check("aaa", set())
        == "Hash not found in local database. This does not mean it's safe."
    )
    assert offline_check(" AAA ", {"aaa"}) == "WARNING: Hash found in local database!"


def test_is_valid_dump():
    assert is_valid_dump("# Last updated: 2026-11-10 14:27:39 UTC   #\nabc\n") == True
    assert is_valid_dump("abc\n") == False
    assert is_valid_dump("# Last updated: 2026-11-10 14:27:39 UTC   #\n") == False
    assert is_valid_dump("") == False
