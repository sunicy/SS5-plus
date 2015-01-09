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

#ifndef SS5MYSQL_H
#define SS5MYSQL_H 1

#define SQLSTRING "SELECT uname FROM grp WHERE gname like"
/*
 *  * SS5: Mysql configuration parameters
 *   */
struct _S5Mysql {
  char IP[16];          /* Mysql ip       */
  char DB[64];          /* Mysql db       */
  char User[64];        /* Mysql user     */
  char Pass[64];        /* Mysql password */
  char SqlString[128];  /* Mysql SQL query base string */
} S5Mysql;


UINT
  MySqlCheck( char *group,
		  char *s5username
);

UINT
  MySqlQuery( pid_t pid,
                  char *group,
                  char *user,
                  int dirid
);

#endif
