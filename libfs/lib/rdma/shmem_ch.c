#include "shmem_ch.h"
#include "messaging.h"
#include "agent.h"

#include <sys/socket.h>
#include <sys/un.h>

#define UDS_SOCKET_PATH "/tmp/kernfs-server.socket"

static ssize_t send_fd_to_libfs(int fd, void *ptr, size_t nbytes, int sendfd);
static void *uds_thread_body(void* arg);
static void handle_connection(int data_socket);

__attribute__((visibility ("hidden"))) 
int shmem_chan_add(int portno, int realfd, int app_type, pid_t pid, int polling)
{
	int sockfd = find_first_empty_bit_and_set(s_conn_bitmap, MAX_CONNECTIONS);	

	if(sockfd < 0)
		mp_die("can't open new connection; number of open sockets == MAX_CONNECTIONS");

	debug_print("adding userspace connection on socket #%d\n", sockfd);

	struct conn_context *ctx = (struct conn_context *)calloc(1, sizeof(struct conn_context));

	ctx->sockfd = sockfd;
	ctx->ch_type = CH_TYPE_LOCAL;
	ctx->portno = portno;
	ctx->realfd = realfd;
	ctx->app_type = app_type;
	ctx->pid = pid;
	ctx->poll_always = polling;
	ctx->poll_enable = 1;

	ctx->msg_send = (struct message **)calloc(MAX_BUFFER, sizeof(struct message*));
	ctx->msg_rcv = (struct message **)calloc(MAX_BUFFER, sizeof(struct message*));

	s_conn_bitmap[sockfd] = 1;
	s_conn_ctx[sockfd] = ctx;

	return sockfd;
}

void shmem_chan_setup(int sockfd, volatile void *send_buf, volatile void *recv_buf)
{
	struct conn_context *ctx = s_conn_ctx[sockfd];

	assert(ctx->ch_type == CH_TYPE_LOCAL);

	size_t full_msg_size = sizeof(struct message) + sizeof(char) * msg_size;

	if(shmem_chan_state_init(ctx, send_buf, recv_buf, full_msg_size))
		mp_die("Failed to initialize local channel");

#if 1
	app_conn_event(sockfd);
#endif
	return;
}

void shmem_chan_disconnect(int sockfd)
{
	struct conn_context *ctx = get_channel_ctx(sockfd);

	app_disc_event(ctx->sockfd);

	ctx->poll_enable = 0;

	close(ctx->realfd);

	set_channel_state(ctx, CH_CONNECTION_TERMINATED);

	printf("Connection terminated [sockfd:%d]\n", ctx->sockfd);

	s_conn_bitmap[ctx->sockfd] = 0;
	s_conn_ctx[ctx->sockfd] = NULL;

	munmap(ctx->msg_send[0], (sizeof(struct message)+sizeof(char)*msg_size) * MAX_BUFFER);
	munmap(ctx->msg_rcv[0], (sizeof(struct message)+sizeof(char)*msg_size) * MAX_BUFFER);

	free(ctx->msg_send);
	free(ctx->msg_rcv);
 
	free(ctx);
}

void shmem_poll_loop(int sockfd)
{
	struct conn_context *ctx = get_channel_ctx(sockfd);
	volatile struct message *recv_msg = NULL;
	//struct app_context app_ctx;
	struct timeval stop, start;
	int n_events = 0;
	uint32_t app_id;
	uint64_t elapsed = 0;
	char ping_msg[1];

	gettimeofday(&start, NULL);
	//do stuff

	// printf("start shmem_poll_loop for sockfd %d\n", ctx->sockfd);
	while(ctx->poll_enable) {
		recv_msg = shmem_recv(ctx);

		if(recv_msg) {
			recv_msg->meta.app.sockfd = ctx->sockfd;

			//adding convenience pointers to data blocks
			recv_msg->meta.app.data = (char *) recv_msg->data;

			app_id = recv_msg->meta.app.id;

			debug_print("application callback: seqn = %u\n", app_id);
			
			app_recv_event((struct app_context *)&recv_msg->meta.app);

			shmem_release_buffer(recv_msg);

			notify_response(ctx, app_id);

			//reset timer
			gettimeofday(&start, NULL);

			n_events++;
		}

#if 1
		// Timeout logic

		gettimeofday(&stop, NULL);
		elapsed = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

		// block if no events received during POLLING_TIMEOUT
		if(elapsed > POLLING_TIMEOUT) {
			debug_print("switching to blocking mode [after: %lu us]\n", elapsed);
			while(n_events >= 0) {
				//Read the message from the server into the buffer
				if(recv(ctx->realfd, ping_msg, 1, 0) <= 0) {
					shmem_chan_disconnect(ctx->sockfd);
					return;
				}
				//debug_print("received message from socket [remaining: %d]\n", n_events);
				n_events--;
			}
			debug_print("exiting blocking mode [remaining: %d]\n", n_events);

			// we should never get here as polling is relatively fast
			// TODO: think of other sanity checks
			if(elapsed > 10 * POLLING_TIMEOUT) {
				for(int i=0; i < MAX_BUFFER; i++)
					debug_print("BUFFER IDX: %d DATA: %s\n", i, ctx->msg_rcv[i]->data);
				debug_print("RECV INDEX: %u\n", ctx->rcv_idx);
				mp_die("Invalid codepath");
			}
		}
#endif

	}

	// printf("end shmem_poll_loop for sockfd %d\n", ctx->sockfd);

}

void * local_client_thread(void *arg)
{
	// printf("In thread\n");

	char send_path[32];
	char recv_path[32];
	char shm_msg[128];
	char init_msg[128];
	int client_socket;
	struct sockaddr_in serv_addr;
	int sockfd = *((int *)arg);

	struct conn_context *ctx = s_conn_ctx[sockfd];

	sleep(1);
	socklen_t addr_size;
	memset(&serv_addr, '0', sizeof(serv_addr));

	client_socket = socket(PF_INET, SOCK_STREAM, 0);
	ctx->realfd = client_socket;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(ctx->portno);
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr_size = sizeof(serv_addr);

	if(connect(client_socket, (struct sockaddr *) &serv_addr, addr_size))
		mp_die("Unable to connect");


#if 0
	strcpy(message,"Hello");
	if(send(client_socket , message , strlen(message) , 0) < 0)
	{
		printf("Send failed\n");
	}
		//Read the message from the server into the buffer
	if(recv(client_socket, buffer, 1024, 0) < 0)
	{
		printf("Receive failed\n");
	}
#endif

	snprintf(init_msg, 128, "%d|%u", ctx->app_type, ctx->pid);

	if(send(ctx->realfd , init_msg , 128, 0) < 0) {
		mp_die("send failed");
	}

	// printf("SEND --> MSG_INIT [pid %s]\n", init_msg);

	if(recv(ctx->realfd, shm_msg, 128, 0) <= 0) {
		mp_die("Receive failed");
	}

	// printf("RECV <-- MSG_SHM [paths: %s]\n", shm_msg);

	split_char(shm_msg, send_path, recv_path);

	size_t total_size = (sizeof(struct message)+sizeof(char)*msg_size) * MAX_BUFFER;
	void * send_addr = mp_create_shm(send_path, total_size);
	void * recv_addr = mp_create_shm(recv_path, total_size);

	shmem_chan_setup(sockfd, send_addr, recv_addr);

	set_channel_state(ctx, CH_CONNECTION_READY);

#if 0
	volatile struct message *recv_msg = NULL;
	struct app_context app_ctx;
	uint32_t app_id;

	while(ctx->poll_enable) {

		recv_msg = shmem_recv(ctx);
		if(recv_msg) {
			app_ctx = recv_msg->meta.app;
			app_recv_event(&app_ctx);
			shmem_release_buffer(recv_msg);
			app_id = recv_msg->meta.app.id;
			notify_response(ctx, app_id);
		}
	}
#endif
	shmem_poll_loop(sockfd);
	//shmem_chan_clear(sockfd);

	printf("Exit client_thread \n");

	pthread_exit(NULL);
}

void * local_server_thread(void *arg)
{
	char send_path[32];
	char recv_path[32];
	char app_str[32];
	char pid_str[32];
	char init_msg[128];
	char shm_msg[128];
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	int sockfd = *((int *)arg);
	struct conn_context *ctx = s_conn_ctx[sockfd];
	//pthread_mutex_lock(&lock);

	snprintf(send_path, 32, "/shm_send_%d", sockfd);
	snprintf(recv_path, 32, "/shm_recv_%d", sockfd);

	size_t total_size = (sizeof(struct message)+sizeof(char)*msg_size) * MAX_BUFFER;
	void * send_addr = mp_create_shm(send_path, total_size);
	void * recv_addr = mp_create_shm(recv_path, total_size);

	memset(send_addr, 0, total_size);
	memset(recv_addr, 0, total_size);

	if(recv(ctx->realfd , init_msg , 128, 0) <= 0) {
		mp_die("Receive failed");
	}

	split_char(init_msg, app_str, pid_str);
	ctx->app_type = atoi(app_str);
	ctx->pid = atol(pid_str);

	// printf("RECV <-- MSG_INIT [pid %d]\n", ctx->app_type);

	shmem_chan_setup(sockfd, send_addr, recv_addr);

	snprintf(shm_msg, 128, "%s|%s", recv_path, send_path);

	if(send(ctx->realfd , shm_msg , 128 , 0) < 0) {
		mp_die("send failed");
	}

	// printf("SEND --> MSG_SHM [paths: %s]\n", shm_msg);

	set_channel_state(ctx, CH_CONNECTION_READY);

#if 0
	volatile struct message *recv_msg = NULL;
	struct app_context app_ctx;
	struct timeval stop, start;
	uint32_t app_id;
	uint64_t elapsed = 0;
	uint64_t n_events = 0;
	char ping_msg[1];

	gettimeofday(&start, NULL);
	//do stuff

	while(ctx->poll_enable) {
		recv_msg = shmem_recv(s_conn_ctx[sockfd]);

		if(recv_msg) {
			app_ctx = recv_msg->meta.app;
			app_recv_event(&app_ctx);
			shmem_release_buffer(recv_msg);

			app_id = recv_msg->meta.app.id;
			notify_response(ctx, app_id);

			//reset timer
			gettimeofday(&start, NULL);

			n_events++;

		}

		gettimeofday(&stop, NULL);
		elapsed = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;

		if(elapsed > POLLING_TIMEOUT) {
			while(n_events >= 0) {
				//Read the message from the server into the buffer
				if(recv(ctx->realfd, ping_msg, 1, 0) <= 0)
					mp_die("Receive failed");

				n_events--;
			}
		}

	}
	
	//pthread_mutex_unlock(&lock);
	close(ctx->realfd);
#endif
	shmem_poll_loop(sockfd);
	//shmem_chan_clear(sockfd);

	printf("Exit server_thread \n");

	pthread_exit(NULL);
}

void * local_server_loop(void *port)
{
	int server_socket, newSocket;
	struct sockaddr_in serv_addr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;

	memset(&serv_addr, '0', sizeof(serv_addr));
	
	server_socket = socket(PF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(port));
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	int yes = 1;
	int ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
	printf("setsockopt return = %d\n", ret);
	if(ret != 0) {
		mp_die("failed to set socketopt");
	}
	if(bind(server_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)))
		mp_die("Error binding socket");

	// unix domain socket
	// struct sockaddr_un uds_addr;
	// int uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	// printf("Server socket fd = %d\n", uds_fd);
	// if (remove(UDS_SOCKET_PATH) == -1 && errno != ENOENT) {
	// 	mp_die("Failed to remove existing Unix Domain socket\n");
	// }

	// memset(&uds_addr, 0, sizeof(struct sockaddr_un));
	// uds_addr.sun_family = AF_UNIX;
	// strncpy(uds_addr.sun_path, UDS_SOCKET_PATH, sizeof(uds_addr.sun_path) - 1);
	// if (bind(uds_fd, (struct sockaddr *) &uds_addr, sizeof(struct sockaddr_un)) == -1) {
	// 	mp_die("Failed to bind unix domain socket");
	// }
	// if (listen(uds_fd, 128) == -1) {
	// 	mp_die("Failed to listen unix domain socket");
	// }
	// pthread_t uds_thread;
	//
	

	//Listen on the socket, with 128 max connection requests queued
	if(listen(server_socket,128)==0)
		printf("[Local-Server] Listening on port %d for connections. interrupt (^C) to exit.\n", atoi(port));
	else
		mp_die("Error listening on socket");
#if 1

	pthread_t uds_thread;
	if(pthread_create(&uds_thread, NULL, uds_thread_body, NULL) != 0)
			mp_die("Failed to create unix domain socket thread");

	int *sock_arg;
	while(1) {
		addr_size = sizeof serverStorage;
		newSocket = accept(server_socket, (struct sockaddr *) &serverStorage, &addr_size);

		sock_arg = malloc(sizeof(int));
		*sock_arg = shmem_chan_add(atoi(port), newSocket, -1, -1, 1);
		printf("Adding connection with sockfd: %d\n", *sock_arg);

		struct conn_context *ctx = get_channel_ctx(*sock_arg);

		if(pthread_create(&ctx->cq_poller_thread, NULL, local_server_thread, sock_arg) != 0 )
			mp_die("Failed to create thread");

	}
#endif
	return NULL;
}

static void *uds_thread_body(void* arg) {
	struct sockaddr_un uds_addr;
	int uds_fd;
    int data_socket;
    
    uds_fd = socket(AF_UNIX, SOCK_STREAM, 0);

	printf("Server socket fd = %d\n", uds_fd);
	if (remove(UDS_SOCKET_PATH) == -1 && errno != ENOENT) {
		perror("Failed to remove existing Unix Domain socket\n");
        exit(-1);
	}

	memset(&uds_addr, 0, sizeof(struct sockaddr_un));
	uds_addr.sun_family = AF_UNIX;
	strncpy(uds_addr.sun_path, UDS_SOCKET_PATH, strlen(UDS_SOCKET_PATH));
	if (bind(uds_fd, (struct sockaddr *) &uds_addr, sizeof(struct sockaddr_un)) == -1) {
		perror("Failed to bind unix domain socket");
        exit(-1);
	}
	if (listen(uds_fd, 128) == -1) {
		perror("Failed to listen unix domain socket");
        exit(-1);
	}

    for(;;) {
		data_socket = accept(uds_fd, NULL, NULL);
		if (data_socket == -1) {
			perror("accept");
			exit(1);
		}
		printf("Got a connection!\n");

		handle_connection(data_socket);
	}
}

static void handle_connection(int data_socket) {
	struct msghdr msg;
	struct iovec iovec[1];
	char buf[1024];

	// msg.
	msg.msg_iovlen = 1;
	msg.msg_iov = iovec;
	// msg.msg_iov[0].iov_len = 13;
	printf("Waiting to receive data\n");
	int ret = recv(data_socket, buf, 1024, 0);
	if(ret <= 0) {
		perror("recvmsg");
		exit(1);
	}
	printf("Read %d amount of data\n", ret);
	printf("Read the following %s\n", buf);

	int fd = open("file.txt", O_RDWR);
	assert(fd >= 0);

	send_fd_to_libfs(data_socket, "", 1, fd);
}

static ssize_t send_fd_to_libfs(int fd, void *ptr, size_t nbytes, int sendfd)
{
	struct msghdr msg;
	struct iovec iov[1];

	union {
		struct cmsghdr cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmptr;

	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof(control_un.control);

	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	*((int *) CMSG_DATA(cmptr)) = sendfd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov[0].iov_base = ptr;
	iov[0].iov_len = nbytes;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	return (sendmsg(fd, &msg, 0));
}
