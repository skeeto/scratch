// ==UserScript==
// @name         Reddit translation via "on-prem" Large Language Model (LLM)
// @description  Usertext elements are passed to a local LLM for translation
// @lastupdated  2024-10-22
// @version      1.0
// @license      Public Domain
// @include      https://old.reddit.com/*
// @grant        none
// ==/UserScript==

// Browser instructions:
// 1. Set up the LLM as instructed below
// 2. Install this user script (Greasemonkey, etc.)
// 3. Press ALT-t on reddit to begin translating posts and comments
//
// Longer comments take more time. Typical comments take a couple of
// seconds depending on your local hardware. The LLM auto-detects the
// source language and can handle pages with a mixture of languages. A
// real-world universal translator! Double-edged sword: Because LLMs are
// so clever, it may refuse to translate a comment when it disapproves
// of its content. Only few years ago, a machine translator refusing to
// operate on moral grounds was just a hamfisted sci-fi metaphor, but
// we're now living in that future.
//
// LLM and server instructions (any operating system):
// 1. Install a C++ compiler (w64devkit, etc.)
// 2. $ git clone https://github.com/ggerganov/llama.cpp
// 3. $ make -j$(nproc)
// 4. Open https://huggingface.co/bartowski/gemma-2-2b-it-GGUF
// 5. Download gemma-2-2b-it-Q4_K_M.gguf
// 6. $ ./llama-server -c 0 -m gemma-2-2b-it-Q4_K_M.gguf
//
// To reply in the foreign language, visit the local web interface to
// your LLM, http://localhost:8080/, and kindly ask it to translate your
// comment into the target language. If you don't know what the local
// language is called, give the LLM a sample and request identification.
// Don't overthink it. Talk to the LLM as you would a human assistant.
//
// Advanced option: gemma-2-9b-it produces slightly better translations
// but is slower and consumes more resources. Even more important when
// translating your own outgoing comments. Mistral-Nemo-Instruct-2407 is
// also a good choice. In either case, probably only worth using if you
// can run inference at least partially on a GPU, where they're faster
// than gemma-2-2b-it on a CPU.
//
// With some work, this script may support other OpenAI-compatable APIs.
// Most are stricter than llama.cpp, and likely require an API token.

async function translate(tag, lang = "English") {
  let url = "http://localhost:8080/v1/chat/completions"
  let response = await fetch(url, {
    method: "POST",
    body: JSON.stringify({
      max_tokens: 4096,
      messages: [{
        role: "system",
        content:
          `You are a translator that translates user messages into ${lang}. ` +
          `Do not respond. Do not explain. Do not elaborate. Only translate. ` +
          `Preserve HTML tags.`
      }, {
        role: "user",
        content: tag.innerHTML,
      }],
    }),
  })
  if (response.ok) {
      let message = await response.json()
      tag.innerHTML = message.choices[0].message.content
  }
}

async function translateAll() {
  let elements = document.querySelectorAll(".usertext-body .md, a.title")
  for (let i = 1; i < elements.length; i++) {
    await translate(elements[i])
  }
}

document.addEventListener("keydown", function(e) {
  if (e.altKey && e.key === "t") {
    translateAll()
  }
})
