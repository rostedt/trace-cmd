#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/vm_sockets.h>

#include "trace-cmd-private.h"

int __hidden trace_vsock_open(unsigned int cid, unsigned int port)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	int sd;

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -errno;

	if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)))
		return -errno;

	return sd;
}

int __hidden trace_vsock_make(unsigned int port)
{
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = port,
	};
	int sd;

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -errno;

	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)))
		return -errno;

	if (listen(sd, SOMAXCONN))
		return -errno;

	return sd;
}

int __hidden trace_vsock_make_any(void)
{
	return trace_vsock_make(VMADDR_PORT_ANY);
}

int __hidden trace_vsock_get_port(int sd, unsigned int *port)
{
	struct sockaddr_vm addr;
	socklen_t addr_len = sizeof(addr);

	if (getsockname(sd, (struct sockaddr *)&addr, &addr_len))
		return -errno;

	if (addr.svm_family != AF_VSOCK)
		return -EINVAL;

	if (port)
		*port = addr.svm_port;

	return 0;
}

int get_vsocket_params(int fd, unsigned int *lcid, unsigned int *rcid)
{
	struct sockaddr_vm addr;
	socklen_t addr_len = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*lcid = addr.svm_cid;

	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*rcid = addr.svm_cid;

	return 0;
}

int trace_vsock_print_connection(int fd)
{
	struct sockaddr_vm vm_addr;
	socklen_t addr_len;
	int cid, port;

	addr_len = sizeof(vm_addr);
	if (getpeername(fd, (struct sockaddr *)&vm_addr, &addr_len))
		return -1;
	if (vm_addr.svm_family != AF_VSOCK)
		return -1;
	cid = vm_addr.svm_cid;
	port = vm_addr.svm_port;
	if (tracecmd_get_debug())
		tracecmd_debug("Connected to @%u:%u fd:%d\n", cid, port, fd);
	else
		tracecmd_plog("Connected to @%u:%u\n", cid, port);
	return 0;
}

static int try_splice_read_vsock(void)
{
	int ret, sd, brass[2];

	sd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sd < 0)
		return -errno;

	ret = pipe(brass);
	if (ret < 0)
		goto out_close_sd;

	/*
	 * On kernels that don't support splice reading from vsockets
	 * this will fail with EINVAL, or ENOTCONN otherwise.
	 * Technically, it should never succeed but if it does, claim splice
	 * reading is supported.
	 */
	ret = splice(sd, NULL, brass[1], NULL, 10, 0);
	if (ret < 0)
		ret = errno != EINVAL;
	else
		ret = 1;

	close(brass[0]);
	close(brass[1]);
out_close_sd:
	close(sd);
	return ret;
}

bool __hidden trace_vsock_can_splice_read(void)
{
	static bool initialized, res;

	if (initialized)
		return res;

	res = try_splice_read_vsock() > 0;
	initialized = true;
	return res;
}

#define GET_LOCAL_CID	0x7b9

int __hidden trace_vsock_local_cid(void)
{
	int cid;
	int fd;

	fd = open("/dev/vsock", O_RDONLY);
	if (fd < 0)
		return -errno;

	if (ioctl(fd, GET_LOCAL_CID, &cid))
		cid = -errno;

	close(fd);
	return cid;
}
