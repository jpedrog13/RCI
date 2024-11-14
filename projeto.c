
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>

extern int errno;

#define max(A,B) ((A)>=(B)?(A):(B))

/*definimos a existencia de 16 chaves no anel*/

int main(int argc, char* argv[]){

int ss=0, auxkey, key, k, uk, servkey, suckey, suc2key;

char buffer[100], buffer2[100], buf[100], sucbuffer[100], sucbuffer2[100];
char predbuffer[100], predbuffer2[100], ubuffer[100], menu[6];
char servip[20], servport[10], ip[20], port[10], sucip[20], sucport[10], suc2ip[20], suc2port[10];
char copy[100], copy2[100], copy3[100], func[20], func2[20], func3[20], func4[20];

int fd, sucfd=-1, predfd=-2, newfd, afd=0, a2fd=0, kfd, ufd, ufd2=-1;
fd_set rfds;
ssize_t bcounter;

enum {idle, busy} state;
enum {idle2, busy2} state2;
enum {idle3, busy3} state3;

struct sockaddr_in addr;
socklen_t addrlen;
struct addrinfo hints,*res;

int n, new=0, fdcounter, maxfd, maxfd2, errcode, mod1, mod2, udpstate=0, nread;

const char check = '\n'; /*detectar o terminador ao analisar o sscanf*/

struct sigaction act;

state = idle;
state2 = idle2;
state3 = idle3;


if(argc==3){
	strcpy(ip, argv[1]);
	strcpy(port, argv[2]);
}
else{
	printf("Insira o seu IP e PORT: <./dkt IP PORT>.\n");
	return 0;
}

memset(&act,0,sizeof act);
act.sa_handler=SIG_IGN;

if(sigaction(SIGPIPE,&act,NULL)==-1)
	exit(1);



////////////////////////////SERVER TCP//////////////////////////////////

/*Código para criação do servidor, mantendo-o aberto com file descriptor
 aqui fd criado*/

	if((fd=socket(AF_INET,SOCK_STREAM,0))==-1)
		exit(1);

	memset(&hints,0,sizeof hints);

	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	hints.ai_flags=AI_PASSIVE;

	if((errcode= getaddrinfo (NULL,port,&hints,&res))!=0)
		exit(1);
		
	if( bind (fd,res->ai_addr,res->ai_addrlen)==-1)
		exit(1);
	
	if( listen (fd,30)==-1)
		exit(1);

	
	
///////////////////////////SERVER UDP///////////////////////////////////
	
/*código criação udp*/
	
	if((ufd=socket(AF_INET,SOCK_DGRAM,0))==-1)
		exit(1);
	
	memset(&hints,0,sizeof hints);
	
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_DGRAM;
	hints.ai_flags=AI_PASSIVE;
	
	if((errcode=getaddrinfo(NULL,port,&hints,&res))!=0)
		exit(1);
	
	if(bind(ufd,res->ai_addr,res->ai_addrlen)==-1)
		exit(1);

//////////////////////////INERFACE//////////////////////////////////////

printf("\nnew i\nsentry i succi succi.IP succi.TCP\nentry"
	   " i boot boot.IP boot.TCP\nleave\nshow\nfind k\nexit\n\n");

////////////////////////////////////////////////////////////////////////

/*ciclo while onde está inserido o select que irá controlar todas
 as operações*/

	while(1){	
		FD_ZERO(&rfds);
		FD_SET(fd,&rfds);
		FD_SET(ufd,&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		
		maxfd=fd;
		
		if(ss==1){
			FD_SET(sucfd, &rfds);
			FD_SET(predfd, &rfds);
			maxfd2=max(sucfd, predfd);
		}
		
		maxfd=max(fd,maxfd2);
		
		if(state==busy){
			FD_SET(afd, &rfds);
			maxfd=max(maxfd, afd);
		}
		
		if(udpstate==1){
			FD_SET(ufd2,&rfds);
			maxfd=max(maxfd, ufd2);	
		}
		
/*operaões de max confirmam os fds que precisam de ser observados e 
calculando o número mais alto de fd (guardado em fdmax) a analisar
para não ser analisado um número excessivo de fd's*/
		
		fdcounter = select(maxfd+1, &rfds, NULL, NULL, NULL);
		
		if(fdcounter<=0) 
			exit(1);
		
		
		
///////////////////////////////MENU/////////////////////////////////////
		
/*é acedido apenas quando há algum input no terminal, sabendo portanto que
se trata de uma opção do menu a analisar*/
		
		if(FD_ISSET(STDIN_FILENO,&rfds)){
			
			if(fgets(buf, 100, stdin)!=NULL){										
				
				sscanf(buf,"%s", menu);
				
				/*variável ss é usada para verificar se o servidor já
				está contido num anel*/
				 
				/*variável new verifica se o servidor se encontra 
				sozinho no anel*/
				
				/*usamos auxkey para verificar se a chave pertence
				ao total de chaves do anel*/
								
				if(strcmp(menu, "exit")==0){
					FD_ZERO(&rfds);
					close(sucfd);
					close(predfd);
					close(fd);
					exit(1);
				}
				else if(strcmp(menu, "new")==0){
					
					/*criação do anel, sendo que como o servidor está
					sozinho assume os valores do sucessor e segundo
					sucessor com os seus não efetuando qualquer ligação.
					Se algum servidor se tentar ligar a si, como new=1,
					para além de aceitar essa ligação irá ligar-se a ele
					também*/					
					
					sscanf(buf, "%s %d", menu, &auxkey);
					
					if(auxkey>0 && auxkey<=16){		
						if(ss==1){
							printf("\nJá está inserido num anel\n");
						}
						else{							
							key = auxkey;
							suckey = key;
							suc2key = key;
							strcpy(sucip, ip);
							strcpy(sucport, port);
							strcpy(suc2ip, ip);
							strcpy(suc2port, port);
							
							sucfd=fd;
							predfd=sucfd;
														
							new=1;
							ss=1;
						}	
					}	
					else{
						printf("\nInsira uma chave entre 1 e 16\n");			
					}		
				}	
				else if(strcmp(menu, "entry")==0){
					
					/*criação de socket udp, para contactar o server udp
					do servidor que conhece no anel a que pretende entrar.*/
					
					/*variável udpstate verifica se o servidor está à
					espera da resposta do servidor que contactou,
					mantendo este socket em aberto*/
					
					sscanf(buf, "%s %d %d %s %s", menu, &auxkey, &servkey, servip, servport);
					
					if(auxkey>0 && auxkey<=16){
					
						if(ss==1){
							printf("\nJá está inserido num anel\n");
						}
						else{
							sprintf(ubuffer, "EFND %d", auxkey);
						
							ufd2=socket(AF_INET,SOCK_DGRAM,0);
							
							if(ufd2==-1)/*error*/exit(1);

							memset(&hints,0,sizeof hints);
							hints.ai_family=AF_INET;
							hints.ai_socktype=SOCK_DGRAM;

							errcode=getaddrinfo(servip,servport,&hints,&res);
							
							if(errcode!=0)/*error*/exit(1);
							
							n=sendto(ufd2,ubuffer,100,0,res->ai_addr,res->ai_addrlen);
							
							if(n==-1)/*error*/exit(1);

							freeaddrinfo(res);
							
							udpstate=1;
							
							FD_SET(ufd2,&rfds);		
						}
					}
					else{
						printf("\nInsira uma chave entre 1 e 16\n");			
					}
				}
				else if(strcmp(menu, "sentry")==0){
					
					/*criação de ligação tcp para se ligar ao servidor
					pretendido*/
					
					sscanf(buf, "%s %d %d %s %s", menu, &auxkey, &suckey, sucip, sucport);
					
					if(auxkey>0 && auxkey<=16){
						if(ss==1){
							printf("\nJá está inserido num anel\n");
						}
						else{							
							sucfd=socket(AF_INET,SOCK_STREAM,0);
								
							if(sucfd==-1)
								exit(1);						
										
							memset(&hints, 0, sizeof hints);
							hints.ai_family=AF_INET;
							hints.ai_socktype=SOCK_STREAM;
												
							n=getaddrinfo(sucip, sucport, &hints, &res);
												
							if(n!=0){
								printf("\nServidor ou Porto errado\n");
								close(sucfd);									
							}
							else{
							
								n=connect(sucfd, res->ai_addr, res->ai_addrlen);

								if(n==-1)
									close(sucfd);										
								else{
								
									key=auxkey;
									sprintf(buf, "NEW %d %s %s\n", key, ip, port);
									
									write(sucfd, buf, 100);
								}
							}							
						}					
						ss=1;
					}
					else{
						printf("\nInsira uma chave entre 1 e 16\n");			
					}
				}
				else if(strcmp(menu, "leave")==0){
					
					if(ss==0){
						printf("\nNão está inserido num anel\n");
					}
					else{
						if(new==1){
							suckey = 0;
							suc2key = 0;
							strcpy(sucip, "");
							strcpy(sucport, "");
							strcpy(suc2ip, "");
							strcpy(suc2port, "");
							sucfd=-1;
							predfd=-2;
							
							ss=0;
							new=0;
						}
						else{
							FD_ZERO(&rfds);
							close(sucfd);
							close(predfd);
							sucfd=-1;
							predfd=-2;											
							ss=0;
						}
					}
				}
				else if(strcmp(menu, "show")==0){
					
					if(ss==0){
						printf("\nNão está inserido num anel\n");
					}
					else{					
						printf("\nnode_key = %d\nnode.IP:node.TCP = %s:%s\nsucc_key = %d\n"
							   "succ.IP:succ.TCP = %s:%s\nSessão TCP com sucessor\n"
							   "Sessão TCP com predecessor\nsucc2_key = %d\n"
							   "succ2.IP:succ2.TCP = %s:%s\n",
							   key, ip, port, suckey, sucip, sucport, suc2key, suc2ip, suc2port);
					}
				}
				else if(strcmp(menu, "find")==0){
					
					/*separamos em 3 casos diferentes*/
								
					sscanf(buf, "%s %d", menu, &k);	

					if(k>0 && k<=16){
						
						mod1=(k-suckey)%16;
						mod2=(k-key)%16;
						
						if(ss==0){
							printf("\nNão está inserido num anel\n");
						}
						else{
							if(key==suckey || k==key){
								
								/*se a chave que procura é a sua ou se
								tem a mesma chave do seu sucessor (está sozinho) 
								sabe que a chave pretendida se encontra em si*/
								
								printf("\nA chave %d encontra-se no servidor: %d\n", k, key);
							}							
							else if(key==suc2key){							
								
								/*se a sua chave é igual à do seu segundo
								sucessor, sabe que existem apenas 2 servidores
								no anel*/
								
								if(k==suckey){
									printf("\nA chave %d encontra-se no servidor: %d\n", k, suckey);
								}
									else{
									if(mod1<0){
										mod1=mod1+16;
									}
									if(mod2<0){
										mod2=mod2+16;
									}
									if(mod1>mod2){
										printf("\nA chave %d encontra-se no servidor: %d\n", k, suckey);
									}
									else{
										printf("\nA chave %d encontra-se no servidor: %d\n", k, key);
									}
								}
							}
							else{
								
								/*se nenhuma das condições anteriores se
								verifica, delega a pesquisa ao seu sucessor*/
															
								sprintf(buf, "FND %d %d %s %s\n", k, key, ip, port);
								
								write(sucfd, buf, 100);
							}
						}
					}
					else{
						printf("\nInsira uma chave entre 1 e 16.\n");			
					}		
				}				
			}
		}



////////////////////NEW DATA FROM SUCC(2+SERVERS)///////////////////////

/*a informação recebida vem de sucfd, ou seja, o seu sucessor*/
/*irá ser analisada do ponto de vista em que somos o cliente tcp*/
/*verifica que existem 2 ou mais servidores no anel*/

		if(FD_ISSET(sucfd,&rfds) && fd!=sucfd && sucfd!=predfd && ss==1){

			if((bcounter=read(sucfd, sucbuffer, 100))!=0){
				 
				if(bcounter==-1){
					close(sucfd);
					state3=busy3;					
				}					
				switch(state3){
					case idle3:
						
						state3=busy3;
						
						while(strchr(sucbuffer, check)==NULL){	
							
							bcounter=read(sucfd, copy3, 100);
							
							if(bcounter>0){
								strcat(sucbuffer, copy3);
							}						
						}
						strcpy(copy3, "");
					
						sscanf(sucbuffer, "%[^\n]s", sucbuffer2);			
													
						sscanf(sucbuffer2, "%s", func3);
						
						/*func3 determina a tarefa a realizar*/
														
						if(strcmp(func3,"NEW")==0){
							
							/*sendo que a tarefa NEW vem do seu sucessor,
							termina a sua ligação com este, cria uma ligação
							com o seu novo sucessor e informa o seu
							predecessor do seu novo sucessor (segundo
							sucessor deste)*/
								
							close(sucfd);
														
							sscanf(sucbuffer2, "%s %d %s %s", func3, &suckey, sucip, sucport);
														
							sucfd=socket(AF_INET,SOCK_STREAM,0);
																		
							if(sucfd==-1)
								exit(1);																	
														
							memset(&hints, 0, sizeof hints);
							hints.ai_family=AF_INET;
							hints.ai_socktype=SOCK_STREAM;
																
							n=getaddrinfo(sucip, sucport, &hints, &res);
		
							if(n!=0)
								exit(1);
			
							n=connect(sucfd, res->ai_addr, res->ai_addrlen);																
								
							if(n==-1)
								exit(1);
								
							else{
					
								sprintf(sucbuffer2, "SUCC %d %s %s\n", suckey, sucip, sucport);					

								write(sucfd, "SUCCCONF\n", 100);
								write(predfd, sucbuffer2, 100);
								
							}	
						}
						else if(strcmp(func3,"SUCC")==0){
							
							/*atualiza os dados do seu segundo sucessor*/
							
							sscanf(sucbuffer2, "%s %d %s %s", func3, &servkey, servip, servport);					
									
							suc2key=servkey;
							strcpy(suc2ip, servip);
							strcpy(suc2port, servport);												
						}
						else if(strcmp(func3,"KEY")==0){
							
							/*recebe a instrução KEY do seu sucessor,
							referindo então onde se encontra a chave que
							procurou*/

							sscanf(sucbuffer2, "%s %d %d %s %s", func3, &k, &servkey, servip, servport);
							
							printf("\nA chave %d encontra-se no servidor: %d\n", k, servkey);
							
							sprintf(ubuffer, "EKEY %d %d %s %s", k, servkey, servip, servport);								
						
							sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
											
						}
						state3 = idle3;
						break;
						
					case busy3:	break;
	
				}			
			}
			
			/*se não conseguiu ler a informação recebida do seu sucessor
			sabe que a sua ligação com este terminou*/
			
			else{			
				if(key==suc2key){
					
					/*neste caso sabe que agora se encontra sozinho,
					por isso não estabelece nenhuma ligação nova (pois
					ambas as ligações que tinha caíram) e simplesmente
					atualiza os seu dados de sucessor e segundo sucessor
					para os seus*/
						
					printf("\nLigação ao sucessor perdida\n");
						
					suckey = key;
					suc2key = key;
					strcpy(sucip, ip);
					strcpy(sucport, port);
					strcpy(suc2ip, ip);
					strcpy(suc2port, port);
						
					sucfd=fd;
					predfd=sucfd;
	
					new=1;
				}
				else{
					
					/*como a primeira condição não se verificou,
					estabelece ligação com o seu segundo sucessor, e
					indorma o seu predecessor do seu novo sucessor 
					(segundo sucessor deste)*/
					
					sucfd=socket(AF_INET,SOCK_STREAM,0);
					
					suckey = suc2key;
					strcpy(sucip, suc2ip);
					strcpy(sucport, suc2port);
					
					if(sucfd==-1)
						exit(1);																	
				
					memset(&hints, 0, sizeof hints);
					hints.ai_family=AF_INET;
					hints.ai_socktype=SOCK_STREAM;
			
					n=getaddrinfo(suc2ip, suc2port, &hints, &res);
			
					if(n!=0)
						exit(1);
			
					n=connect(sucfd, res->ai_addr, res->ai_addrlen);																
		
					if(n==-1)
						exit(1);
	
					else{
						printf("\nLigação ao sucessor perdida. Pedido de ligação efetuado\n");
				
						sprintf(sucbuffer2, "SUCC %d %s %s\n", suc2key, suc2ip, suc2port);
						
						write(sucfd, "SUCCCONF\n", 100);
						write(predfd, sucbuffer2, 100);
	
					}
				}
				state3=idle3;
			}			
		}



////////////////////NEW DATA FROM PRED(2+SERVERS)///////////////////////

/*a informação recebida vem de predfd, ou seja, o seu predecessor*/
/*irá ser analisada do ponto de vista em que somos o servidor tcp*/
/*verifica que existem 2 ou mais servidores no anel*/

		if(FD_ISSET(predfd,&rfds) && fd!=predfd && sucfd!=predfd && ss==1){
			
			if((bcounter=read(predfd, predbuffer, 100))!=0){
				 
				if(bcounter==-1){
					close(predfd);
					state3=busy3;					
				}	

				switch(state2){
					case idle2: 
					
						state2=busy2; 
						
						while(strchr(predbuffer, check)==NULL){	
							
							bcounter=read(predfd, copy2, 100);
							
							if(bcounter>0){
								strcat(predbuffer, copy2);
							}						
						}
						strcpy(copy2, "");
																	
						sscanf(predbuffer, "%[^\n]s", predbuffer2);			
													
						sscanf(predbuffer2, "%s", func2);
						
						/*func2 determina a tarefa a realizar*/
														
						if(strcmp(func2,"FND")==0){
							
							/*com o comando FND tem que verificar se sabe
							onde a chave pedida se encontra ou se delega
							ao seu sucessor*/
							
							sscanf(predbuffer2, "%s %d %d %s %s", func2, &k, &servkey, servip, servport);
							
							mod1=(k-suckey)%16;
							mod2=(k-key)%16;
							
							if(mod1<0){
								mod1=mod1+16;
							}
							if(mod2<0){
								mod2=mod2+16;
							}
							if(k==key){
								
								/*sabe que tem a chave logo cria ligação
								com o servidor que a pediu para o
								informar*/
								
								kfd=socket(AF_INET,SOCK_STREAM,0);
								
								if(kfd==-1)
									exit(1);																	
							
								memset(&hints, 0, sizeof hints);
								hints.ai_family=AF_INET;
								hints.ai_socktype=SOCK_STREAM;
						
								n=getaddrinfo(servip, servport, &hints, &res);
						
								if(n!=0)
									exit(1);
						
								n=connect(kfd, res->ai_addr, res->ai_addrlen);																
					
								if(n==-1)
									exit(1);
				
								else{
				
									sprintf(predbuffer2, "KEY %d %d %s %s\n", k, key, ip, port);

									write(kfd, predbuffer2, 100);
									
									sprintf(ubuffer, "EKEY %d %d %s %s", k, key, ip, port);
						
									sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
								}
								
							}
							else if(servkey==key){
								
								/*se foi ele pŕoprio a perguntar pela chave
								sabe que ja percorreu o anel inteiro então a
								chave só se pode encontrar no seu sucessor*/
								
								printf("\nA chave %d encontra-se no servidor: %d\n", k, suckey);
								
								sprintf(ubuffer, "EKEY %d %d %s %s", k, suckey, sucip, sucport);										
						
								sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);										
							}
							else if(mod1>mod2){
								
								/*se a chave se encontra mais perto do seu
								sucessor do que de si sabe que esta se
								encontra nele. estabele a ligação tcp
								com o servidor que iniciou a pesquisa*/
								
								kfd=socket(AF_INET,SOCK_STREAM,0);
								
								if(kfd==-1)
									exit(1);																	
							
								memset(&hints, 0, sizeof hints);
								hints.ai_family=AF_INET;
								hints.ai_socktype=SOCK_STREAM;
						
								n=getaddrinfo(servip, servport, &hints, &res);
						
								if(n!=0)
									exit(1);
						
								n=connect(kfd, res->ai_addr, res->ai_addrlen);																
					
								if(n==-1)
									exit(1);
				
								else{

									sprintf(predbuffer2, "KEY %d %d %s %s\n", k, suckey, sucip, sucport);

									write(kfd, predbuffer2, 100);
									
									sprintf(ubuffer, "EKEY %d %d %s %s", k, key, ip, port);								
						
									sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
								}							
							}
							else{
								
								/*se nenhuma das condições anteriores se
								verifica delega a pesquisa ao seu sucessor*/
								
								sprintf(predbuffer2, "FND %d %d %s %s\n", k, servkey, servip, servport);
								
								write(sucfd, predbuffer2, 100);
							}
						
						}
						else if(strcmp(func2,"KEY")==0){
							
							/*recebeu KEY do seu predecessor, informa o
							utilizador de onde esta se encontra*/
						
							sscanf(predbuffer2, "%s %d %d %s %s", func2, &k, &servkey, servip, servport);
							
							printf("\nA chave %d encontra-se no servidor: %d\n", k, servkey);
							
							sprintf(ubuffer, "EKEY %d %d %s %s", k, servkey, servip, servport);										
						
							sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
						
						}
						state2=idle2;
					
						break;
				
					case busy2: break;
				}
			}
		}


		
//////////////////NEW DATA FROM NEW CLIENT(2+SERVERS)///////////////////

/*recebe informação de um servidor desconhecido*/
/*irá ser analisada do ponto de vista em que somos o servidor tcp*/
/*verifica que existem 2 ou mais servidores no anel*/
			
		if(FD_ISSET(fd,&rfds) && fd!=0 && fd!=sucfd && fd!=predfd && ss==1){
				
			addrlen=sizeof(addr);
				
			if((newfd=accept(fd,(struct sockaddr*)&addr,&addrlen))==-1)
				exit(1);
							
			switch(state){
				case idle: afd=newfd; state=busy; break;
				case busy: write(newfd, "busy\n", 5); close(newfd); break;
			}
		}
		if(FD_ISSET(afd,&rfds) && afd!=0 && fd!=0 && fd!=sucfd && fd!=predfd && ss==1){
				
			if((bcounter=read(afd, buffer, 100))!=0){ 
				if(bcounter==-1){
					close(afd);
					afd=0;
				}
				else{					
					while(strchr(buffer, check)==NULL){	
							
						bcounter=read(sucfd, copy, 100);
							
						if(bcounter>0){
							strcat(buffer, copy);
						}						
					}
					strcpy(copy, "");
									
					sscanf(buffer, "%[^\n]s", buffer2);				
					
					sscanf(buffer2, "%s", func);
					
					/*func determina a tarefa a realizar*/
						
					if(strcmp(func,"NEW")==0){
						
						/*se recebe NEW de um servidor desconhecido
						define este como sendo seu predecessor, e informa
						o seu predecessor antigo do seu novo predecessor
						(que será sucessor deste)*/
						
						sscanf(buffer2, "%s %d %s %s", func, &servkey, servip, servport);					
						
						sprintf(buffer2, "NEW %d %s %s\n", servkey, servip, servport);								
						write(predfd, buffer2, 100);
						
						sprintf(buffer2, "SUCC %d %s %s\n", suckey, sucip, sucport);
						write(afd, buffer2, 100);
						
						predfd = afd;
						
						afd=0;
					}
					else if(strcmp(func,"KEY")==0){
						
						/*recebe KEY de um servidor desconhecido, informa
						o utilizador de onde se encontra a chave e termina
						a ligação com o servidor que o informou*/
						
						sscanf(buffer2, "%s %d %d %s %s", func, &k, &servkey, servip, servport);
							
						printf("\nA chave %d encontra-se no servidor: %d\n", k, servkey);
						
						sprintf(ubuffer, "EKEY %d %d %s %s", k, servkey, servip, servport);
						
						sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
						
						close(afd);
						
						afd=0;
					}							
					else if(strcmp(func,"SUCCCONF")==0){
						
						/*atualiza o seu predecessor para o servidor que
						o contactou e informa o seu predecessor do seu
						novo sucessor (2 sucessor deste)*/
						
						predfd=afd;		
						
						sprintf(buffer2, "SUCC %d %s %s\n", suckey, sucip, sucport);
						
						write(predfd, buffer2, 100);
			
						afd=0;						
					}
				}
				state = idle;			
			}
			else{	
				state = idle;
				close(afd);
				afd=0;
			}	
		}



//////////////////////////NEW DATA(1-SERVER)////////////////////////////

/*recebe informação de um servidor desconhecido sabendo que se encontra
sozinho no anel*/
/*irá ser analisada do ponto de vista em que somos o servidor tcp*/

		if(FD_ISSET(fd,&rfds) && fd!=0 && fd==sucfd && fd==predfd && ss==1){
			
			addrlen=sizeof(addr);
				
			if((newfd=accept(fd,(struct sockaddr*)&addr,&addrlen))==-1)
				exit(1);
							
			switch(state){
				case idle: state=busy; afd=newfd; break;				
				
				case busy: write(newfd, "busy\n", 5); close(newfd); break;
			}
		}
		if(FD_ISSET(afd,&rfds) && afd!=0 && fd!=0 && fd==sucfd && fd==predfd && ss==1){
				
			if((bcounter=read(afd, buffer, 100))!=0){ 
				if(bcounter==-1){
					close(afd);
					afd=0;
				}
				else{			
					while(strchr(buffer, check)==NULL){	
							
						bcounter=read(sucfd, copy, 100);
							
						if(bcounter>0){
							strcat(buffer, copy);
						}						
					}
					strcpy(copy, "");
									
					sscanf(buffer, "%[^\n]s", buffer2);				
					
					sscanf(buffer2, "%s", func);
					
					/*func determina a tarefa a realizar*/
					
					if(strcmp(func,"NEW")==0){
						
						/*recebendo NEW e sabendo que está sozinho no anel,
						não só guarda a ligação do seu novo predecessor,
						como estabelece uma ligação com este, que será também 
						seu sucessor (nesta ligação estabelecida é cliente tcp)*/		
						
						sscanf(buffer2, "%s %d %s %s", func, &servkey, servip, servport);					
						
						a2fd=socket(AF_INET,SOCK_STREAM,0);
								
						if(a2fd==-1)
							exit(1);						
						
						memset(&hints, 0, sizeof hints);
						hints.ai_family=AF_INET;
						hints.ai_socktype=SOCK_STREAM;
								
						n=getaddrinfo(servip, servport, &hints, &res);
								
						if(n!=0){
							close(afd);
							close(a2fd);
							afd=0;
							a2fd=0;
						}
						else{	
							n=connect(a2fd, res->ai_addr, res->ai_addrlen);
								
							if(n==-1){
								close(afd);
								close(a2fd);
								afd=0;
								a2fd=0;
							}
							else{
								sucfd=a2fd;
								predfd=afd;
								suckey=servkey;
								strcpy(sucip, servip);
								strcpy(sucport, servport);
								
								sprintf(buffer2, "SUCC %d %s %s\n", suckey, sucip, sucport);
			
								write(sucfd, "SUCCCONF\n", 20);
								write(predfd, buffer2, 100);
								
								afd=0;
								a2fd=0;
							}
						}
					}
					
				}
				state=idle;			
			}
			else{	
				state=idle;
				afd=0;
			}	
		}							



////////////////////////////NEW DATA UDP////////////////////////////////

/*analisa a informação udp recebida*/
/*sempre que é descoberta uma chave noutra parte do código é enviada uma
mensagem udp para o caso do servidor estar à espera de receber esta
informação*/

		if(FD_ISSET(ufd,&rfds)){
			
			addrlen=sizeof(addr);
			
			nread=recvfrom(ufd,ubuffer,100,0,(struct sockaddr*)&addr,&addrlen);
				
			if(nread==-1)
				exit(1);
				
			sscanf(ubuffer, "%s %i", func4, &uk);
			
			if(strcmp(func4, "EFND")==0){
				
				/*responde onde a chave se encontra se souber, ou inicia
				a sua pesquisa dentro do anel*/
						
				mod1=(uk-suckey)%16;
				mod2=(uk-key)%16;
						
					if(key==suckey || uk==key){
								
						sprintf(ubuffer,"EKEY %d %d %s %s", uk, key, ip, port);
						
						sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);
					}							
					else if(key==suc2key){							
								
						if(mod1<0){
							mod1=mod1+16;
						}
						if(mod2<0){
							mod2=mod2+16;
						}
						if(mod1>mod2){
								
							sprintf(ubuffer,"EKEY %d %d %s %s", uk, suckey, sucip, sucport);
						
							sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);		
						}
						else{
										
							sprintf(ubuffer,"EKEY %d %d %s %s", uk, key, ip, port);	
						
							sendto(ufd,ubuffer,nread,0,(struct sockaddr*)&addr,addrlen);			
						}
					}
					else{								
						sprintf(ubuffer,"FND %d %d %s %s\n", uk, key, ip, port);
								
						write(sucfd, ubuffer, 100);
					}
				
			}
		}		
		if(FD_ISSET(ufd2,&rfds)){
			
			if(strcmp(func4, "EKEY")==0){
				
				/*obtem a informação de onde se encontra a chave e inicia
				a ligação com o seu novo sucessor*/
				
				sucfd=socket(AF_INET,SOCK_STREAM,0);
								
					if(sucfd==-1)
						exit(1);						
										
					memset(&hints, 0, sizeof hints);
					hints.ai_family=AF_INET;
					hints.ai_socktype=SOCK_STREAM;
												
					n=getaddrinfo(sucip, sucport, &hints, &res);
												
					if(n!=0){
						printf("\nServidor ou Porto errado\n");
						close(sucfd);									
					}
					else{
							
						n=connect(sucfd, res->ai_addr, res->ai_addrlen);

						if(n==-1)
							close(sucfd);										
						else{
							printf("\nPedido de ligação efetuado\n");
									
							key=auxkey;
							sprintf(buf, "NEW %d %s %s\n", key, ip, port);
										
							write(sucfd, buf, 100);
						}
					}							
			ss=1;
			udpstate=0;
			}	
		}
	}

return 0;
}

						
