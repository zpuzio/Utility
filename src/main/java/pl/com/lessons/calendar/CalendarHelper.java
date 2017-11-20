package pl.com.lessons.calendar;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CalendarHelper {
	public static final String FORMAT_DATETIME = "yyyy-MM-dd HH:mm:ss";
    public static String formatDate(String format, Date date)
    {
        if (date == null)
        {
            return "";
        } else
        {
            SimpleDateFormat dateFormat = new SimpleDateFormat(format);
            return dateFormat.format(date);
        }
    }

}
