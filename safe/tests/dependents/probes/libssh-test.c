#include <libssh/libssh.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        return 1;
    }

    int port = 2222;
    ssh_options_set(session, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, "sshuser");

    if (ssh_connect(session) != SSH_OK) {
        return 2;
    }
    if (ssh_userauth_password(session, NULL, "secretpw") != SSH_AUTH_SUCCESS) {
        return 3;
    }

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
        return 4;
    }
    if (ssh_channel_open_session(channel) != SSH_OK) {
        return 5;
    }
    if (ssh_channel_request_exec(channel, "printf libssh-ok") != SSH_OK) {
        return 6;
    }

    char buffer[128];
    int n = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
    if (n < 0) {
        return 7;
    }
    buffer[n] = '\0';

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    return strcmp(buffer, "libssh-ok") == 0 ? 0 : 8;
}
