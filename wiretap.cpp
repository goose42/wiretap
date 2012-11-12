#include <iostream>
#include <stdio.h>


#include "read_fns.h"
using std::cout;
using std::endl;



int main(int argc,char* argv[])
{
	FILE *input_file;

	if (argc != 2) //check if correct number of arguments
	{
		cout<<"Incorrect method to execute wiretap."<<endl<<"Please run wiretap with the following command:"<<endl<<"\t./wiretap <pcap dump file name>"<<endl;
		return 0;
	}
	input_file = fopen(argv[1], "r"); //open file

	if (input_file == NULL) //check if file opens correctly.
	{
		cout<<"Error with opening file, please check the file name"<<endl;
		return 0;
	}  

	//once file is opened, pass it into the pcap method to read and make sense of
	cap_file::pcap_read(input_file); 

	return 0;
}





