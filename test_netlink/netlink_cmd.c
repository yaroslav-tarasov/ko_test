#include <stdio.h>
#include <stdlib.h>

#include <netlink/netlink.h>

#define MY_MSG_TYPE (0x10 + 2)  // + 2 is arbitrary but is the same for kern/usr



int
main(int argc, char *argv[])
{

#ifdef HAVE_LIBNL3
	struct nl_sock *nls;
#else
	struct nl_handle *nls;
#endif

    char msg[] = { 0xde, 0xad, 0xbe, 0xef, 0x90, 0x0d, 0xbe, 0xef };
    int ret=0;
#ifdef HAVE_LIBNL3
     nls = nl_socket_alloc();
#else
     nls = nl_handle_alloc();
#endif


    if (!nls) {
        printf("bad nl_socket_alloc\n");
        return EXIT_FAILURE;
    }

    ret = nl_connect(nls, NETLINK_USERSOCK);
    if (ret < 0) {
        nl_perror(ret, "nl_connect");
#ifdef HAVE_LIBNL3
        nl_socket_free(nls);
#else
	nl_handle_destroy(nls);
#endif
        return EXIT_FAILURE;
    }


    ret = nl_send_simple(nls, MY_MSG_TYPE, 0, msg, sizeof(msg));

    if (ret < 0) {
        nl_perror(ret, "nl_send_simple");
        nl_close(nls);
#ifdef HAVE_LIBNL3
        nl_socket_free(nls);
#else
	nl_handle_destroy(nls);
#endif
        return EXIT_FAILURE;
    } else {
        printf("sent %d bytes\n", ret);
    }

    nl_close(nls);
#ifdef HAVE_LIBNL3
    nl_socket_free(nls);
#else
	nl_handle_destroy(nls);
#endif

    return EXIT_SUCCESS;
}
