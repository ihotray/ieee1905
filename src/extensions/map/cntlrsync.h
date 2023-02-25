#ifndef DYN_CNTLR_SYNC_H
#define DYN_CNTLR_SYNC_H


struct sync_config {
	uint32_t len;
	uint8_t *data;
};


int build_sync_config_request(uint8_t *aladdr, uint8_t **m1, uint16_t *m1_size,
			      void **key);


int build_sync_config_response(uint8_t *m1, uint16_t m1_size,
			       struct sync_config *cred,
			       uint8_t **m2, uint16_t *m2_size);

int process_sync_config_response(uint8_t *m1, uint16_t m1_size, void *key,
				 uint8_t *m2, uint16_t m2_size,
				 struct sync_config *out);


#endif /* DYN_CNTLR_SYNC_H */
