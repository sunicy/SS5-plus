/* Socks Server 5
 * Copyright (C) 2011 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef SS5MOD_STATISTICS_H
#define SS5MOD_STATISTICS_H 1

/*
 * Initialize module context
 */
UINT
  InitModule(	struct _module *m
);

/*
 * Master function: browse statistics information
 */
INT
  Statistics(	struct _SS5ClientInfo *ci,
		struct _SS5Socks5Data *sd
);

UINT
  Summary(	UINT autheerr,
		UINT authoerr,
		UINT cmderr
);

#endif
