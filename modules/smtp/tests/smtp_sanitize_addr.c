#include "../smtp.h"

SmtpProxy *dummy;

int exit_code = 0;

#define SAFE_STR(x)  ((x) ? x : "(NULL)")

void
test_case(gchar *path, gchar *email, gboolean expected)
{
  GString *result = g_string_sized_new(128);
  gchar *end = 0;
  
  if (smtp_sanitize_address(dummy, result, path, TRUE, &end) == expected)
    {
      /* printf("result->str=%s\n", result->str); */    /* for parser debugging */
      if (expected && strcmp(result->str, email) == 0)
        printf("success, path=%s, email=%s, end=%s\n", path, email, end);
      else if (!expected)
        printf("success, path=%s, end=%s\n", path, end);
      else
	{
	  printf("failure, different email, path=%s, email=%s, end=%s\n", path, email, end);
	  exit_code = 1;
	}
      
    }
  else
    {
      printf("failure, different parsing, path=%s, email=%s, result=%s, end=%s\n", path, email, result->str, end);
      exit_code = 1;
    }
  g_string_free(result, TRUE);
}

int
main()
{
  dummy = (SmtpProxy *) z_object_new(Z_CLASS(SmtpProxy));
  dummy->append_domain = g_string_sized_new(0);
  /* z_charset_parse(&dummy.local_part, "a-zA-Z0-9\\-=._"); */
  test_case("<bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<>", "", TRUE);
  test_case("<@hop1,@hop2,@hop3:bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<@:bazsi@balabit.hu>", NULL, FALSE);
  test_case("<:bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1@bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1\"bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1:;bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1,bazsi@balabit.hu>", NULL, FALSE);
  test_case("<bazsi@balabit.hu", NULL, FALSE);
  test_case("bazsi@balabit.hu>", NULL, FALSE);
  test_case("bazsi@balabit.hu", NULL, FALSE);
  test_case("<bazsibalabit.hu>", NULL, FALSE);
  test_case("<\"balazs scheidler\"@balabit.hu>", "\"balazs scheidler\"@balabit.hu", TRUE);
  test_case("<\"balazs scheidler\"@[1.2.3.4]>", "\"balazs scheidler\"@[1.2.3.4]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@[1.2.3.4]>", "\"balazs scheidler\"@[1.2.3.4]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@[domain literal]>", "\"balazs scheidler\"@[domain literal]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@#123456>", "\"balazs scheidler\"@#123456", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@#123456z>", NULL, FALSE);
  test_case("<bounce-debian-gcc=asd=balabit.hu@lists.debian.org> SIZE=10037", "bounce-debian-gcc=asd=balabit.hu@lists.debian.org", TRUE);
  test_case("bazsi@balabit.hu", NULL, FALSE);
  test_case("<bazsi@balabit.hu", NULL, FALSE);
  test_case("bazsi@balabit.hu>", NULL, FALSE);
  dummy->permit_omission_of_angle_brackets = TRUE;
  printf("------\n");
  test_case("bazsi@balabit.hu", "bazsi@balabit.hu", TRUE);
  test_case("<bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<bazsi@balabit.hu", "bazsi@balabit.hu", FALSE);
  test_case("bazsi@balabit.hu>", "bazsi@balabit.hu", FALSE);
  test_case("bounce-debian-gcc=asd=balabit.hu@lists.debian.org SIZE=10037", "bounce-debian-gcc=asd=balabit.hu@lists.debian.org", TRUE);
  return exit_code;
}
