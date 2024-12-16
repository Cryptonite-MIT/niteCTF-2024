#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void main()
{
        setvbuf(stdin,NULL,2,0);
        setvbuf(stdout,NULL,2,0);
	puts("Even with my hooked arm,me and my crew shall explore this cruel sea and get rich!");

        int choice,sze,idx;
        char *p[15];
        int s[15];
        while(1)
        {
                printf("1.Get huge chest\n2.Make the lazy people walk the plank\n3.Fill your chests!\n4.Make the quartermaster review the profit\n>");
                scanf("%d",&choice);
                if(choice == 1)
                {
                        printf("Chest number:");
                        scanf("%d",&idx);
                        printf("Chest size:");
                        scanf("%d",&sze);
                        if(idx<0 || idx>15)
                                break;
			if(sze<0 || sze >0x100)
				break;
                        p[idx] = malloc(sze);
                        s[idx] = sze;
                }

                else if(choice ==2)
                {
                        printf("Idiot crew memebr #:");
                        scanf("%d",&idx);
                        if(idx<0 || idx>15)
                                break;
                        free(p[idx]);
                }
                else if(choice==3)
                {
                        printf("Chest nunmber:\n>");
                        scanf("%d",&idx);
			getchar();
                        fgets(p[idx],s[idx],stdin);
                }
                else if(choice ==4)
                {
                        printf("Chest no:");
                        scanf("%d",&idx);
                        if(idx<0 || idx >15)
                                break ;
                        write(1,p[idx],s[idx]);
                }
                else
                        break;
        }
}
