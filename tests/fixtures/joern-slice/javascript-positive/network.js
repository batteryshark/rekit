export async function download(url) {
  const response = await fetch(url);
  return response.text();
}
