/**
 * Copyright 2014 Alexander Solovets
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

static char *
genpass(const char *nick, const char *master)
{
#define PASS_LEN 8
  static char pass[PASS_LEN + 1];
  char md5[MD5_DIGEST_LENGTH];
  MD5_CTX md5ctx;
  BIO *bio, *b64;
  char *base64;
  size_t len;
  int i, j;

  MD5_Init(&md5ctx);
  /* Concatenate the master password with the nickname (in that order!). */
  MD5_Update(&md5ctx, master, strlen(master));
  MD5_Update(&md5ctx, nick, strlen(nick));
  /* Generate the MD5 hash of the concatenated string. */
  MD5_Final(md5, &md5ctx);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  BIO_push(b64, bio);
  /* Convert the MD5 hash to URL-safe Base64. */
  BIO_write(b64, md5, MD5_DIGEST_LENGTH);
  BIO_flush(b64);
  len = BIO_get_mem_data(b64, &base64);

  /* See if there are any digits in the first 8 characters. */
  /* Use the first 8 characters as the account password. */
  while (i < len && !isdigit(base64[i])) { ++i; }
  if (i >= PASS_LEN) {
    /* If no digits are found... */
    /* Search for the first uninterrupted substring of digits. */
    j = i;
    while (j < len && isdigit(base64[j])) { ++j; }
    if (j > i) {
      len = (j - i > PASS_LEN) ? PASS_LEN : j - i;
      /* If a substring of digits is found, prepend them to the Base64 string. */
      strncpy(pass, base64 + i, len);
      strncpy(pass + len, base64, PASS_LEN - len);
    } else {
      /* If no substring is found, prepend a 1. */
      pass[0] = '1';
      strncpy(pass + 1, base64, PASS_LEN - 1);
    }
  } else {
    strncpy(pass, base64, PASS_LEN);
  }
  BIO_free_all(b64);

  /* Make the password URL-safe. */
  for (i = 0; i < PASS_LEN; ++i) {
    if (pass[i] == '+') {
      pass[i] = '-';
    } else if (pass[i] == '/') {
      pass[i] = '_';
    }
  }

  return pass;
}

static void
on_response(GtkDialog *dialog, gint response, gpointer data)
{
  static const char cliptool[] = "xclip -sel clipboard";
  GtkEntry **creds;
  FILE *p;

  if( G_LIKELY(response == GTK_RESPONSE_OK) ) {
    creds = (GtkEntry **) data;
    p = popen(cliptool, "w");
    fputs(genpass(gtk_entry_get_text(creds[0]),
                  gtk_entry_get_text(creds[1])),
          p);
    pclose(p);

    g_print("Account password copied to the clipboard using '");
    g_print(cliptool);
    g_print("'\n");
  }

  gtk_main_quit();
}


gint
main (gint argc, gchar *argv[])
{
#define _(x) x
  gtk_init(&argc, &argv);

  GtkWidget *win = NULL;
  GtkWidget *hbox;
  GtkWidget *creds[2];

  win = gtk_dialog_new_with_buttons(_("GOplop"),
                                    NULL,
                                    GTK_DIALOG_NO_SEPARATOR,
                                    GTK_STOCK_CANCEL,
                                    GTK_RESPONSE_CANCEL,
                                    GTK_STOCK_OK,
                                    GTK_RESPONSE_OK,
                                    NULL);
  gtk_dialog_set_alternative_button_order((GtkDialog *) win,
                                          GTK_RESPONSE_OK,
                                          GTK_RESPONSE_CANCEL,
                                          -1);
  gtk_dialog_set_default_response((GtkDialog *) win, GTK_RESPONSE_OK);
  creds[0] = gtk_entry_new();

  gtk_entry_set_activates_default( (GtkEntry*) creds[0], TRUE );
  hbox = gtk_hbox_new(FALSE, 2);
  gtk_box_pack_start((GtkBox *) hbox, gtk_label_new(_("Nickname:")),
                     FALSE, FALSE, 4);
  gtk_box_pack_start((GtkBox*) hbox, creds[0], TRUE, TRUE, 4);
  gtk_box_pack_start((GtkBox*) ((GtkDialog*)win)->vbox,
                     hbox, FALSE, FALSE, 8 );
  hbox = gtk_hbox_new(FALSE, 2);
  gtk_box_pack_start((GtkBox *) hbox, gtk_label_new(_("Master password:")),
                     FALSE, FALSE, 4);
  creds[1] = gtk_entry_new();
  gtk_entry_set_activates_default((GtkEntry *) creds[1], TRUE );
  gtk_entry_set_visibility((GtkEntry *) creds[1], FALSE);
  gtk_box_pack_start((GtkBox*) hbox, creds[1], TRUE, TRUE, 4);
  gtk_box_pack_start((GtkBox*) ((GtkDialog*)win)->vbox,
                     hbox, FALSE, FALSE, 8 );

  g_signal_connect(win, "response", G_CALLBACK(on_response), creds);

  gtk_window_set_position( (GtkWindow*)win, GTK_WIN_POS_CENTER );
  gtk_window_set_default_size( (GtkWindow*)win, 400, -1 );
  gtk_widget_show_all(win);
  gtk_widget_show(win);

  gtk_window_present(GTK_WINDOW(win));
  gtk_main();

  return EXIT_SUCCESS;
}
