
/** @file main.c
 *  @brief main file for the secure application
 *
 *  This file content the initialization code for the secure application
 *	and non-secure application. NOTE RTC and tamper pin PA08 will be initialized 
 *	manually because they are not correctly supported by Atmel START
 *
 *	@author Quang Hai Nguyen
 *
 *	@date	29.05.2019 - initial 
 *
 *  @bug No known bugs.
 */


#include <atmel_start.h>
#include "Secure_functions/Secure_Functions.h"
#include "cryptoauthlib.h"
#include "atca_host.h"



/* Define section -----------------------------------------------------------------------*/

/* TZ_START_NS: Start address of non-secure application */
#define TZ_START_NS			0x00008000
#define DATA_OFFSET_IN_RAM	0x00
#define REVISION_SIZE		0x04
#define TRUST_RAM_SIZE		128

/* Handle the response status from the secure element*/
#define CHECK_STATUS(s)										\
if(s != ATCA_SUCCESS) {										\
	printf("status code: 0x%x\r\n", s);						\
	printf("Error: Line %d in %s\r\n", __LINE__, __FILE__); \
	while(1);												\
}


/* Local variable section -----------------------------------------------------------------*/

/* typedef for non-secure callback functions */
typedef void (*ns_funcptr_void) (void) __attribute__((cmse_nonsecure_call));

/**	
 *	@brief data structure for secure element instant
 *	
 *	It contains the information to initialize the communication between controller and secure element
 */
ATCAIfaceCfg cfg_ateccx08a_i2c_host = {
	.iface_type				= ATCA_I2C_IFACE,
	.devtype				= ATECC508A,
	.atcai2c.slave_address	= 0xC0,
	.atcai2c.bus			= 1,
	.atcai2c.baud			= 400000,
	.wake_delay				= 800,
	.rx_retries				= 20,
	.cfg_data              = &I2C_0
};


ATCAIfaceCfg cfg_ateccx08a_i2c_remote = {
	.iface_type				= ATCA_I2C_IFACE,
	.devtype				= ATECC608A,
	.atcai2c.slave_address	= 0xC2,
	.atcai2c.bus			= 1,
	.atcai2c.baud			= 400000,
	.wake_delay				= 800,
	.rx_retries				= 20,
	.cfg_data              = &I2C_0
};


typedef struct {
	uint8_t pub_key[64];
} asymm_public_key_t;

typedef struct {
	uint8_t signature[64];
} asymm_signature_t;

//Step 4.1
typedef struct {
	asymm_public_key_t issuer_key;
	asymm_public_key_t subject_key;
	asymm_signature_t signature;
} asymm_certificate_t;

asymm_public_key_t key_store[4] = {
	
	//Step 3.5
	0x67, 0x51, 0x50, 0x54, 0x59, 0x23, 0xdc, 0x6a,
	0x8c, 0xbc, 0xe5, 0x26, 0x90, 0x04, 0xe8, 0xa5,
	0x66, 0xbc, 0x12, 0xa8, 0xcc, 0xce, 0xd7, 0xa8,
	0x6d, 0xf0, 0x9a, 0x5f, 0xd6, 0xb0, 0xd9, 0xf9,
	0x89, 0x40, 0x45, 0xe5, 0x43, 0xa9, 0xce, 0xe7,
	0x39, 0x91, 0xb9, 0xe3, 0xd5, 0x55, 0xe7, 0xb2,
	0x82, 0x76, 0x79, 0x6f, 0x03, 0x4b, 0x40, 0x4c,
	0x87, 0x48, 0x16, 0xd8, 0xc8, 0xd0, 0x23, 0xe4,
	//Step 5.7

	//Step 4.4

}; //cut and paste in remote public key

uint8_t pub[64] = {
	0x67, 0x51, 0x50, 0x54, 0x59, 0x23, 0xdc, 0x6a,
	0x8c, 0xbc, 0xe5, 0x26, 0x90, 0x04, 0xe8, 0xa5,
	0x66, 0xbc, 0x12, 0xa8, 0xcc, 0xce, 0xd7, 0xa8,
	0x6d, 0xf0, 0x9a, 0x5f, 0xd6, 0xb0, 0xd9, 0xf9,
	0x89, 0x40, 0x45, 0xe5, 0x43, 0xa9, 0xce, 0xe7,
	0x39, 0x91, 0xb9, 0xe3, 0xd5, 0x55, 0xe7, 0xb2,
	0x82, 0x76, 0x79, 0x6f, 0x03, 0x4b, 0x40, 0x4c,
	0x87, 0x48, 0x16, 0xd8, 0xc8, 0xd0, 0x23, 0xe4
};

/* Local function prototype section --------------------------------------------------------*/

/**
 *  @brief Print a bytes on the console terminal
 *
 *	@param	ptr		pointer to byte array to print
 *	@param	size	number of byte to print	
 *	
 *	@return	NULL	always return
 *
 *	@date	29.05.2019 - initial 
 *
 *  @bug No known bugs.
 */
static void print_bytes(uint8_t * ptr, uint8_t length);

void asymmetric_auth(void);

int main(void)
{
	
	volatile ATCA_STATUS status;
	uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];
	uint8_t revision_number[REVISION_SIZE];
	uint8_t ram_buff[TRUST_RAM_SIZE];
	
	/* Pointer to Non secure reset handler definition*/
	ns_funcptr_void NonSecure_ResetHandler;
	
	/* Initializes MCU, drivers and middleware */
	atmel_start_init();
	
	asymmetric_auth();
	
#if 0	
	sc_ConsolePuts((uint8_t *)"hello world from secure application\r\n");
	
	/*Initial TrustRAM and display its content*/
	sc_RTC_Init();
	sc_TRAM_Init();
	sc_ReadWholeRAM(ram_buff, TRUST_RAM_SIZE);
	print_bytes(ram_buff,TRUST_RAM_SIZE);
	
	/*Intial ATECC508, read out revision number, serial number and write them to TrustRAM*/
	status = atcab_init( &cfg_ateccx08a_i2c_host );
	CHECK_STATUS(status);
	
	sc_ConsolePuts((uint8_t *)"Initializing ATECC508\r\n");
	
	status = atcab_read_serial_number((uint8_t*)&serial_number);
	CHECK_STATUS(status);
	status = atcab_info(revision_number);
	CHECK_STATUS(status);
	
	sc_TRAM_Write(serial_number, ATCA_SERIAL_NUM_SIZE, DATA_OFFSET_IN_RAM);
	sc_TRAM_Write(revision_number, REVISION_SIZE, DATA_OFFSET_IN_RAM + ATCA_SERIAL_NUM_SIZE);
	
	sc_ConsolePuts((uint8_t *)"ATECC508 is initialized. Revision and serial number are stored in Trust Ram\r\n");
	
	
	
	/* Set non-secure main stack (MSP_NS) */
	__TZ_set_MSP_NS(*((uint32_t *)(TZ_START_NS)));
	
	/* Get non-secure reset handler */
	NonSecure_ResetHandler = (ns_funcptr_void)(*((uint32_t *)((TZ_START_NS) + 4U)));
	
	/* Start Non-secure Application */
	NonSecure_ResetHandler();
#endif

	
	
	/* Replace with your application code */
	while (1) {
		
		
	}
}

static void print_bytes(uint8_t * ptr, uint8_t length)
{
	
	uint8_t i = 0;
	uint8_t line_count = 0;
	for(;i < length; i++) {
		printf("0x%02x, ",ptr[i]);
		line_count++;
		if(line_count == 8) {
			printf("\r\n");
			line_count = 0;
		}
	}
	
	printf("\r\n");
}


void asymmetric_auth(void) 
{

	printf("CryptoAuthLib Basics Disposable Asymmetric Auth\n\r");

		printf("Authentication in progress\n\r");
		volatile ATCA_STATUS status;
		status = atcab_init( &cfg_ateccx08a_i2c_host );
		CHECK_STATUS(status);
		printf("Device init complete\n\r");

		uint8_t nonce[32]; 
		uint8_t signature[64];
		
		status = atcab_random((uint8_t*)&nonce);
		CHECK_STATUS(status);
		printf("Random from host\r\n");
		print_bytes((uint8_t*)&nonce, 32);
		
		status = atcab_init( &cfg_ateccx08a_i2c_remote );
		
		uint8_t slot = 4;
		status = atcab_sign(slot, (const uint8_t*)&nonce, (uint8_t*)&signature);
		CHECK_STATUS(status); 
		printf("Signature from remote\r\n");
		print_bytes((uint8_t*)&signature, 64);
		
		//Step 3.4
		uint8_t temp_pubk[64];
		status = atcab_get_pubkey(slot, &temp_pubk); 
		CHECK_STATUS(status);
		printf("Remote disposable public key\r\n");
		print_bytes((uint8_t*)&temp_pubk, 64);
		//Step 3.6
		
		status = atcab_init( &cfg_ateccx08a_i2c_host ); 
		CHECK_STATUS(status);
		
		bool verify = false;
		bool key_found = false;
		uint8_t i = 0;
		
		for(;i < sizeof(key_store)/sizeof(asymm_public_key_t); i++) {
			if(memcmp(&key_store[i], &temp_pubk, 64) == 0) {
				key_found = true; 
				break;
			}
		}
		
		if(key_found) {
			status = atcab_verify_extern(nonce,signature, key_store[0].pub_key, &verify);
			CHECK_STATUS(status);
			
			//Step 5.7   
			const uint8_t transport_key[] = {           
				0xf2, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x11,          
				0x11, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x11,     
				0x11, 0x11, 0x11, 0x2f,         
				};        
			uint8_t private_key_slot = 4;   
			uint8_t transport_key_slot = 2;        
			//calculate ECDH value   
			uint8_t ecdh_value[32]; 
			//pre-master secret (pms)   
			status = atcab_ecdh_enc(private_key_slot, key_store[0].pub_key, ecdh_value, transport_key, transport_key_slot);        
			CHECK_STATUS(status);   
			printf("ECDH Value\r\n"); 
			printf("Remote Pubic Key * Host Private Key = \r\n"); 
			print_bytes((uint8_t*)&ecdh_value, 32);
			printf("\r\n"); 
			
		}
		else{
			printf("no key found\r\n");
		}
			
		if(verify) {
			printf("Authenticated by host\r\n");
			} else {
			printf("Failed to authenticate\r\n");
		}
	
	
}