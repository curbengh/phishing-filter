// Decode O365 Safelinks
// https://support.microsoft.com/en-us/office/advanced-outlook-com-security-for-microsoft-365-subscribers-882d2243-eab9-4545-a58a-b36fee4a46e2
import { createInterface } from "node:readline"

for await (const line of createInterface({ input: process.stdin })) {
  const inputUrl = new URL(`http://${line}`)
  const outputUrl = new URL(inputUrl.searchParams.get('url'))
  console.log(`${outputUrl.host}${outputUrl.pathname}${outputUrl.search}`)
}
