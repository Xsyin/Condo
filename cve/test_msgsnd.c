#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define N_MSG 0x100
static int qid_A[N_MSG]     = {0};

void send_msg(int qid, int size, int type, int c)
{
    struct msgbuf
    {
        long mtype;
        char mtext[size];
    } msg;

    msg.mtype = type;
    // memset(msg.mtext, c, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), 0) == -1)
    {
        perror("[X] msgsnd");
        exit(1);
    }
}

void alloc_msg_queue_A(int id)
{
    if ((qid_A[id] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT)) == -1)
    {
        perror("[X] msgget");
        exit(1);
    }
}

void close_queue(int qid)
{
    if (msgctl(qid, IPC_RMID, NULL) < 0)
    {
        perror("[X] msgctl()");
        exit(1);
    }
}

int main(){
    for (int i = 0; i < N_MSG; i++){
        alloc_msg_queue_A(i);
    }
    for (int i = 0; i < N_MSG; i++){
        send_msg(qid_A[i], 0xfd0+0x18, 1, 'A');
    }

    for (int i = 0; i < N_MSG; i++){
        close_queue(qid_A[i]);
    }
    return 0;
}