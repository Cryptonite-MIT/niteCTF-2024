#include<stdio.h>
#include<string.h>

int main()
{
	setvbuf(stdin,NULL,2,0);
	setvbuf(stdout,NULL,2,0);
	char buf[100];

	while(1)
	{
		char c = ' ';
		printf("What gift do you want from santa\n>");
		fgets(buf,sizeof(buf),stdin);
		printf("Santa brought you a ");
		printf(buf);
		puts("do you want another gift?\nEnter y or n:");
		scanf("%c",&c);
		if('n'==c)
			break;	
		getchar();
	}
}
	
		
