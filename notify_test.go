package main

import "testing"

func TestEscapeMarkdown(t *testing.T) {
	got := escapeMarkdown("a_b*[c]`d`")
	want := "a\\_b\\*\\[c]\\`d\\`"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestParseTelegramURL(t *testing.T) {
	token, chatID, threadID, err := parseTelegramURL("telegram://123:abc@telegram?chats=456:789&preview=No")
	if err != nil {
		t.Fatal(err)
	}
	if token != "123:abc" || chatID != "456" || threadID != "789" {
		t.Fatalf("unexpected parse result token=%q chatID=%q threadID=%q", token, chatID, threadID)
	}

	token, chatID, threadID, err = parseTelegramURL("telegram://token@telegram?chats=456")
	if err != nil {
		t.Fatal(err)
	}
	if token != "token" || chatID != "456" || threadID != "" {
		t.Fatalf("unexpected parse result token=%q chatID=%q threadID=%q", token, chatID, threadID)
	}

	if _, _, _, err := parseTelegramURL("telegram://token@telegram"); err == nil {
		t.Fatal("expected missing chats error")
	}
}
