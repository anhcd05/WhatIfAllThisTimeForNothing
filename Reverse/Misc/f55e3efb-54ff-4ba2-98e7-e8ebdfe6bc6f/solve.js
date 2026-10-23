for (var day = 16; day <= 31; day++){

    for (var month = 1; month <= 12; month++){

        for (var year = 1; year <= 99; year++){

            dayStr = (day < 10 ? "0" : "") + String(day)
            monthStr = (month < 10 ? "0" : "") + String(month)
            yearStr = (year < 10 ? "0" : "") + String(year)

            res = yearStr + monthStr + dayStr
            if (_0x9a220(res))
                console.log(res)
        }
    }
}


