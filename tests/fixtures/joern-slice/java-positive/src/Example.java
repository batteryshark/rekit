final class Example {
    interface Client {
        String download(String url);
    }

    static void launch(Client client, String url) throws Exception {
        String payload = client.download(url);
        Runtime.getRuntime().exec(payload);
    }
}
