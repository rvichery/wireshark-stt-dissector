/* packet-stt.c
 *
 * Routines for Stateless Transport Tunneling (STT) packet dissection
 * Remi Vichery <remi.vichery@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Protocol ref:
 * http://tools.ietf.org/html/draft-davie-stt-06
 */


#include "config.h"

#include <epan/packet.h>

/* IANA  ref: 
 * http://www.iana.org/assignments/service-names-port-numbers/service-
 * names-port-numbers.xml 
 */
#define TCP_PORT_STT  7471 

void proto_register_stt(void);
void proto_reg_handoff_stt(void);


#define STT_PCP_MASK    0xE000
#define STT_V_MASK      0x1000
#define STT_VLANID_MASK 0x0FFF

static int proto_stt = -1;


static int hf_stt_version = -1;
static int hf_stt_flags = -1;
static int hf_stt_flag_b7 = -1;
static int hf_stt_flag_b6 = -1;
static int hf_stt_flag_b5 = -1;
static int hf_stt_flag_b4 = -1;
static int hf_stt_flag_b3 = -1;
static int hf_stt_flag_b2 = -1;
static int hf_stt_flag_b1 = -1;
static int hf_stt_flag_b0 = -1;
static int hf_stt_l4_offset = -1;
static int hf_stt_reserved_8 = -1;
static int hf_stt_max_seg_size = -1;
static int hf_stt_pcp = -1;
static int hf_stt_v = -1;
static int hf_stt_vlan_id= -1;
static int hf_stt_context_id = -1;
static int hf_stt_padding = -1;


static int ett_stt = -1;
static int ett_stt_flgs = -1;


static dissector_handle_t eth_handle;

static void
dissect_stt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *stt_tree, *flg_tree;
    proto_item *ti, *flg_item;
    tvbuff_t *next_tvb;
    int offset = 0;

    /* Make entry in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STT");

    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_stt, tvb, offset, -1, ENC_NA);
    stt_tree = proto_item_add_subtree(ti, ett_stt);

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Version      | Flags         |  L4 Offset    |  Reserved     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Max. Segment Size          | PCP |V|     VLAN ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                     Context ID (64 bits)                      +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Padding                   |    Data                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                                                               |
*/

    flg_item = proto_tree_add_item(stt_tree, hf_stt_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flg_tree = proto_item_add_subtree(flg_item, ett_stt_flgs);

    proto_tree_add_item(flg_tree, hf_stt_flag_b7, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b6, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b5, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b4, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b3, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flg_tree, hf_stt_flag_b0, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(stt_tree, hf_stt_reserved_24, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset+=3;

    proto_tree_add_item(stt_tree, hf_stt_vni, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset+=3;


    proto_tree_add_item(stt_tree, hf_stt_reserved_8, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(eth_handle, next_tvb, pinfo, tree);

}


/* Register STT with Wireshark */
void
proto_register_stt(void)
{
    static hf_register_info hf[] = {
        { &hf_stt_version,
          { "Version", "stt.version",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL
          },
        },
        { &hf_stt_flags,
          { "Flags", "stt.flags",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b7,
          { "Flags", "stt.flags.b7",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b6,
          { "Flags", "stt.flags.b6",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b5,
          { "Flags", "stt.flags.b5",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b4,
          { "Flags", "stt.flags.b4",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b3,
          { "Flags", "stt.flags.b3",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b2,
          { "Flags", "stt.flags.b2",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b1,
          { "Flags", "stt.flags.b4",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL,
          },
        },
        { &hf_stt_flag_b0,
          { "Flags", "stt.flags.b0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL,
          },
        },
        { &hf_stt_l4_offset,
          { "L4 Offset", "stt.l4offset",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL,
          },
        },
        { &hf_stt_reserved_8,
          { "Reserved", "stt.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL,
          },
        },
        { &hf_stt_max_seg_size,
          { "Max Segment Size", "stt.max_seg_size",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL,
          },
        },
        { &hf_stt_pcp,
          { "Max Segment Size", "stt.max_seg_size",
            FT_UINT16, BASE_DEC, NULL, STT_PCP_MASK,
            NULL, HFILL,
          },
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_stt,
        &ett_stt_flgs,
    };

    /* Register the protocol name and description */
    proto_stt = proto_register_protocol("Stateless Transport Tunneling",
                                          "STT", "stt");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_stt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


}

void
proto_reg_handoff_stt(void)
{
    dissector_handle_t stt_handle;

    eth_handle = find_dissector("eth");

    stt_handle = create_dissector_handle(dissect_stt, proto_stt);
    dissector_add_uint("tcp.port", TCP_PORT_STT, stt_handle);
    dissector_add_handle("tcp.port", stt_handle);  /* For 'Decode As' */

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
