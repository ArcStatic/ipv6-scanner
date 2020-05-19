#include <stdio.h>
#include "bgpstream.h"

int main(int argc, const char **argv)
{
  bgpstream_t *bs = bgpstream_create();
  bgpstream_record_t *record;
  bgpstream_elem_t *elem;
  char buffer[1024];

  /* Define the prefix to monitor: 2403:f600::/32 */
  bgpstream_pfx_t my_pfx;
  if(bgpstream_str2pfx( "2403:f600::/32", &my_pfx) == NULL)
    {
      fprintf(stderr, "Error: invalid prefix\n");
      return -1;
    }
  
  /* Set metadata filters */
  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_COLLECTOR, "rrc00");
  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_COLLECTOR, "route-views2");
  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_RECORD_TYPE, "updates");
  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_ELEM_IP_VERSION, "6");
  /* Time interval: 01:20:10 - 06:32:15 on Tue, 12 Aug 2014 UTC */
  bgpstream_add_interval_filter(bs, 1407806410, 1407825135);

  /* Start the stream */
  bgpstream_start(bs);

  /* Read the stream of records */
  while (bgpstream_get_next_record(bs, &record) > 0) {
    /* Ignore invalid records */
    if (record->status != BGPSTREAM_RECORD_STATUS_VALID_RECORD) {
      continue;
    }
    /* Extract elems from the current record */
    while (bgpstream_record_get_next_elem(record, &elem) > 0) {
      //only interested in active prefixes (ie. announcements (and RIBs?))
      if ((elem->type == BGPSTREAM_ELEM_TYPE_ANNOUNCEMENT)
           || (elem->type == BGPSTREAM_ELEM_TYPE_RIB)){
        /* Print the prefix information */
        bgpstream_pfx_snprintf(buffer, 1024, &(elem->prefix));
        fprintf(stdout, "%s\n", buffer);
      }
    }
  }

  bgpstream_destroy(bs);
  return 0;
}
