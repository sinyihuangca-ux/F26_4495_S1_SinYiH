interface AIKeyConfig {
  provider: "gemini" | "claude" | "openai";
  key: string;
}

export async function callAIWithFallback(prompt: string, keys: AIKeyConfig[]): Promise<string> {
  if (!keys || keys.length === 0) {
    throw new Error("No API keys provided. Please configure at least one AI key.");
  }

  let lastError: any = null;

  for (const { provider, key } of keys) {
    if (!key || !key.trim()) continue;

    try {
      console.log(`[+] Attempting AI analysis with provider: ${provider}`);

      if (provider === "gemini") {
        const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=${key}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.2 },
          }),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error.message);
        return data.candidates[0].content.parts[0].text;
      } 
      
      else if (provider === "claude") {
        const res = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "anthropic-dangerous-direct-browser-access": "true", // Required if called directly from browser client
          },
          body: JSON.stringify({
            model: "claude-3-5-sonnet-20241022",
            max_tokens: 1000,
            messages: [{ role: "user", content: prompt }],
          }),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error.message);
        return data.content[0].text;
      } 
      
      else if (provider === "openai") {
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${key}`,
          },
          body: JSON.stringify({
            model: "gpt-4o",
            messages: [{ role: "user", content: prompt }],
            temperature: 0.2,
          }),
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error.message);
        return data.choices[0].message.content;
      }
    } catch (err) {
      console.warn(`[-] Provider ${provider} failed. Cycling to next key...`, err);
      lastError = err;
    }
  }

  throw new Error(`All configured AI providers failed. Last error: ${lastError?.message || "Unknown error"}`);
}