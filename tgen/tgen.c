#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#define DATALEN 65536

int port = 5556;

void
onchild ()
{
  int pid;
  int status;

  while (1)
    {
      pid = waitpid (-1, &status, WNOHANG);
      if (pid <= 0)
	break;
    }
}

int
main (int argc, char **argv)
{
  int listenfd, connfd, n;
  int one = 1;
  struct sockaddr_in servaddr, cliaddr;
  socklen_t clilen;
  pid_t childpid;
  char *data;
  char *dummy;

  signal (SIGCHLD, onchild);

  data = calloc (1, DATALEN + 1);
  memset (data, 'E', DATALEN);
  dummy = calloc (1, DATALEN + 1);
  memset (dummy, 'D', DATALEN);

  if (argc >= 2)
    {
      port = atoi (argv[1]);
    }

  fprintf (stderr, "Binding to port %d\n", port);

  listenfd = socket (AF_INET, SOCK_STREAM, 0);

  setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

  bzero (&servaddr, sizeof (servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
  servaddr.sin_port = htons (port);
  if (0 != bind (listenfd, (struct sockaddr *) &servaddr, sizeof (servaddr)))
    {
      fprintf (stderr, "Cannot bind: %m\n");
      exit (1);
    }

  listen (listenfd, 1024);

  while (1)
    {
      clilen = sizeof (cliaddr);
      connfd = accept (listenfd, (struct sockaddr *) &cliaddr, &clilen);

      int flags = fcntl (connfd, F_GETFL, 0);
      fcntl (connfd, F_SETFL, flags | O_NONBLOCK);

      if ((childpid = fork ()) == 0)
	{
	  close (listenfd);

	  fd_set readfds;
	  fd_set writefds;
	  struct timeval timeout;
	  int towrite = 1;
	  int result;
	  int quit = 0;
	  int selecterrno = 0;

	  while (1)
	    {
	      FD_ZERO (&readfds);
	      FD_ZERO (&writefds);

	      FD_SET (connfd, &readfds);
	      if (towrite)
		{
		  FD_SET (connfd, &writefds);
		}

	      do
		{
		  if (!towrite)
		    {
		      timeout.tv_sec = 1;
		      timeout.tv_usec = 0;
		      towrite = 1;
		    }
		  else
		    {
		      timeout.tv_sec = 0;
		      timeout.tv_usec = 1 + (rand () % 1000L) * 100L;
		      towrite = 0;
		    }
		  result =
		    select (1 + connfd, &readfds, &writefds, NULL, &timeout);

		  selecterrno = errno;

		  /* process signals */
		  quit = 0;
		}
	      while ((result == -1) && (selecterrno == EINTR) && !quit);

	      if (FD_ISSET (connfd, &writefds))
		{
		  int writtenbytes =
		    write (connfd, data, 1 + rand () % DATALEN);
		  if (writtenbytes <= 0)
		    {
		      fprintf (stderr, "Write failed\n");
		      close (connfd);
		      exit (0);
		    }
		}

	      if (FD_ISSET (connfd, &readfds))
		{
		  int readbytes = read (connfd, dummy, DATALEN);
		  fprintf (stderr, "Read %d bytes\n", readbytes);
		  if (readbytes <= 0)
		    {
		      fprintf (stderr, "Read failed\n");
		      close (connfd);
		      exit (0);
		    }
		}
	    }
	  close (connfd);
	}
    }
  exit (0);
}
