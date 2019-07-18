
/* Include section-----------------------------------------------------------------------------------*/
#include <atmel_start.h>
#include "trustzone_veneer.h"

/* Define section------------------------------------------------------------------------------------*/
#define TRUST_RAM_SIZE		128


int main(void)
{
	uint8_t ram_buff[TRUST_RAM_SIZE];
	
	/* Initializes MCU, drivers and middleware */
	atmel_start_init();
	
	nonsecure_ConsolePuts("Hello World from non secure application\r\n");
	
	
	/* Replace with your application code */
	while (1) {
		
		/*Waiting for user input to read the data from Trust RAM*/
		nonsecure_ConsolePuts("\r\n\r\n");
		nonsecure_ConsolePuts("Press SW0 to print the content in RAM\r\n");
		while(gpio_get_pin_level(SW0));
		
		/* Read data from Trust RAM and print on Terminal*/
		nonsecure_ReadWholeRAM(ram_buff, TRUST_RAM_SIZE);
		nonsecure_ConsolePuts("Data in RAM:\r\n");
		nonsecure_PrintBytes(ram_buff, TRUST_RAM_SIZE);
		
		delay_ms(500);
	}
}
