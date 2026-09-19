defmodule ExldapUnitTest do
  @moduledoc "Tests that run without an LDAP server."
  use ExUnit.Case

  describe "Exldap.SearchResult.from_record/1" do
    test "converts the 3 field record (OTP 24.3+)" do
      entries = [{:eldap_entry, ~c"CN=a", []}]
      result = Exldap.SearchResult.from_record({:eldap_search_result, entries, [], :asn1_NOVALUE})
      assert %Exldap.SearchResult{entries: ^entries, referrals: []} = result
    end

    test "converts the legacy 2 field record (pre OTP 24.3)" do
      entries = [{:eldap_entry, ~c"CN=a", []}]
      result = Exldap.SearchResult.from_record({:eldap_search_result, entries, []})
      assert %Exldap.SearchResult{entries: ^entries, referrals: []} = result
    end

    test "round trips through to_record" do
      record = {:eldap_search_result, [], [], []}
      assert record == record |> Exldap.SearchResult.from_record() |> Exldap.SearchResult.to_record()
    end

    test "rejects other records" do
      assert_raise FunctionClauseError, fn ->
        apply(Exldap.SearchResult, :from_record, [{:eldap_entry, ~c"CN=a", []}])
      end
    end
  end

  describe "Exldap.Entry.from_record/1" do
    test "converts an entry record and round trips" do
      record = {:eldap_entry, ~c"CN=a,DC=example,DC=com", [{~c"cn", [~c"a"]}]}
      entry = Exldap.Entry.from_record(record)
      assert entry.object_name == ~c"CN=a,DC=example,DC=com"
      assert Exldap.get_attribute(entry, "cn") == {:ok, "a"}
      assert Exldap.Entry.to_record(entry) == record
    end
  end

  describe "Exldap.extensibleMatch/2" do
    test "converts matchingRule and type to charlists" do
      filter = Exldap.extensibleMatch("2", [{:type, "userAccountControl"}, {:matchingRule, "1.2.840.113556.1.4.803"}])
      assert filter == :eldap.extensibleMatch(~c"2", [{:type, ~c"userAccountControl"}, {:matchingRule, ~c"1.2.840.113556.1.4.803"}])
    end

    test "passes dnAttributes boolean through unchanged (issue #15)" do
      attrs = [{:matchingRule, "1.2.840.113556.1.4.1941"}, {:type, "member"}, {:dnAttributes, true}]
      filter = Exldap.extensibleMatch("CN=blaggo", attrs)
      assert {:extensibleMatch, {:MatchingRuleAssertion, ~c"1.2.840.113556.1.4.1941", ~c"member", ~c"CN=blaggo", true}} = filter

      assert {:extensibleMatch, {:MatchingRuleAssertion, _, _, _, false}} =
               Exldap.extensibleMatch("x", [{:type, "member"}, {:dnAttributes, false}])
    end
  end

  describe "filter builders" do
    test "substrings accepts a tuple or a list" do
      assert Exldap.substrings("sn", {:initial, "smi"}) == :eldap.substrings(~c"sn", [{:initial, ~c"smi"}])
      assert Exldap.substrings("sn", [{:any, "mi"}, {:final, "th"}]) == :eldap.substrings(~c"sn", [{:any, ~c"mi"}, {:final, ~c"th"}])
    end

    test "simple filters convert fields to charlists" do
      assert Exldap.present("objectClass") == :eldap.present(~c"objectClass")
      assert Exldap.approxMatch("cn", "Test") == :eldap.approxMatch(~c"cn", ~c"Test")
      assert Exldap.lessOrEqual("n", "1") == :eldap.lessOrEqual(~c"n", ~c"1")
      assert Exldap.greaterOrEqual("n", "1") == :eldap.greaterOrEqual(~c"n", ~c"1")
      assert Exldap.negate(Exldap.present("a")) == :eldap.not(:eldap.present(~c"a"))
    end
  end

  describe "SID conversion" do
    @binary_sid <<0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x98, 0xA2, 0x2A, 0xBD,
                  0x72, 0xAA, 0x6F, 0xB0, 0xE9, 0x66, 0x28, 0x3F, 0x2C, 0x23, 0x00, 0x00>>
    @string_sid "S-1-5-21-3173687960-2960108146-1059612393-9004"

    test "sid_to_string" do
      assert Exldap.sid_to_string(@binary_sid) == @string_sid
    end

    test "string_to_sid" do
      assert Exldap.string_to_sid(@string_sid) == @binary_sid
    end
  end

  describe "verify_credentials/3" do
    test "rejects blank passwords without touching the connection" do
      assert Exldap.verify_credentials(nil, "CN=x", "") == {:error, :invalidCredentials}
      assert Exldap.verify_credentials(nil, "CN=x", ~c"") == {:error, :invalidCredentials}
    end
  end
end
