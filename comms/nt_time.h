#ifndef NT_TIME_H
#define NT_TIME_H

#include "nt_common.h"

typedef struct
{
	int	sec;	/* seconds */
	int	ns;	/* nanoseconds */
}
nt_timespec_t;

#if 0
/* time zone offset */
typedef struct
{
	char	tz_sign;	/* '+' or '-' */
	int	tz_hour;
	int	tz_min;
}
nt_timezone_t;
#endif

#define nt_timespec_compare(t1, t2)	\
	((t1)->sec == (t2)->sec ? (t1)->ns - (t2)->ns : (t1)->sec - (t2)->sec)

typedef enum
{
	NT_TIME_UNIT_UNKNOWN,
	NT_TIME_UNIT_SECOND,
	NT_TIME_UNIT_MINUTE,
	NT_TIME_UNIT_HOUR,
	NT_TIME_UNIT_DAY,
	NT_TIME_UNIT_WEEK,
	NT_TIME_UNIT_MONTH,
	NT_TIME_UNIT_YEAR,
	NT_TIME_UNIT_ISOYEAR,
	NT_TIME_UNIT_COUNT
}
nt_time_unit_t;

double		nt_time(void);
void		nt_timespec(nt_timespec_t *ts);
void		nt_timespec_normalize(nt_timespec_t *ts);
double		nt_current_time(void);
int		nt_is_leap_year(int year);
void		nt_get_time(struct tm *tm, long *milliseconds, nt_timezone_t *tz);
long		nt_get_timezone_offset(time_t t, struct tm *tm);
struct tm	*nt_localtime(const time_t *time, const char *tz);
const struct tm	*nt_localtime_now(const time_t *time);
int		nt_utc_time(int year, int mon, int mday, int hour, int min, int sec, int *t);
int		nt_day_in_month(int year, int mon);
nt_uint64_t	nt_get_duration_ms(const nt_timespec_t *ts);

nt_time_unit_t	nt_tm_str_to_unit(const char *text);
int	nt_tm_parse_period(const char *period, size_t *len, int *multiplier, nt_time_unit_t *base, char **error);
void	nt_tm_add(struct tm *tm, int multiplier, nt_time_unit_t base);
void	nt_tm_sub(struct tm *tm, int multiplier, nt_time_unit_t base);
void	nt_tm_round_up(struct tm *tm, nt_time_unit_t base);
void	nt_tm_round_down(struct tm *tm, nt_time_unit_t base);
const char	*nt_timespec_str(const nt_timespec_t *ts);
int	nt_get_week_number(const struct tm *tm);
int	nt_is_time_suffix(const char *str, int *value, int length);
int	nt_calculate_sleeptime(int nextcheck, int max_sleeptime);

char	*nt_age2str(time_t age);
char	*nt_date2str(time_t date, const char *tz);
char	*nt_time2str(time_t time, const char *tz);
int	nt_iso8601_utc(const char *str, time_t *time);

typedef enum
{
	TIMEPERIOD_TYPE_ONETIME = 0,
/*	TIMEPERIOD_TYPE_HOURLY,*/
	TIMEPERIOD_TYPE_DAILY = 2,
	TIMEPERIOD_TYPE_WEEKLY,
	TIMEPERIOD_TYPE_MONTHLY
}
nt_timeperiod_type_t;

void	nt_ts_get_deadline(nt_timespec_t *ts, int sec);
int	nt_ts_check_deadline(const nt_timespec_t *deadline);

#endif /* NT_TIME_H */
