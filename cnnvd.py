# -*- coding: utf-8 -*-

"""
    Analysis the CNNVD database.

    Last commit info:
    ~~~~~~~~~~~~~~~~~
    $LastChangedDate: 11/12/2019
    $Annotation: Create.
    $Author: xiyan19
"""


import pandas as pd
import re


if __name__ == '__main__':
    # Inputted Parameters
    FILE_database = 'Databases/cnnvd5.xlsx'
    FILE_mainkeywords = 'MainKeywords'
    FILE_minorkeywords = 'MinorKeywords'

    # Outputted Items - [year, rank, keywords]
    data_out = {'year': [], 'rank': [], 'keywords': []}

    # Extracting Keywords.
    dictionary = set()

    with open(FILE_mainkeywords, 'r') as handle1:
        for line in handle1:
            dictionary.add(line[:-1])

    with open(FILE_minorkeywords, 'r') as handle2:
        for line in handle2:
            dictionary.add(line[:-1])

    # Loading the database by pandas.
    df = pd.read_excel(FILE_database)

    # Traversing by rows.
    for row in df.itertuples():
        # We record the multiple keywords contained in vulnerability.
        keywords = set()
        for keyword in dictionary:
            if keyword in str(getattr(row, "affect_software")):
                keywords.add(keyword)

        # Is it a browsers and extensions vulnerability?
        if len(keywords) > 0:
            # For 'cve-xxxx-yyyy', we use 'xxxx' as the year of vulnerability.
            m = re.search(r'(\d{4})-(\d{4})', str(getattr(row, "cve")))
            year = m.group(1)
            if year is None:
                print('[-] ValueError: Year is None.')
                raise ValueError

            # We split 'CVSS2_exploitablity_score' into 3 groups (as 0~3, 3~7, 7~10).
            score = str(getattr(row, "risk"))
            if score == '低危':
                rank = 'low'
            elif score == '中危':
                rank = 'mid'
            elif score == '高危':
                rank = 'high'
            elif score == '超危':
                rank = 'very high'
            else:
                continue
                # print('[-] ValueError: Rank is ' + score + '.')
                # raise ValueError

            # Add this row in result.
            data_out['year'].append(year)
            data_out['rank'].append(rank)
            data_out['keywords'].append(' '.join(keywords))

    # Outputting results into a new excel.
    pd.DataFrame(data=data_out).to_excel(FILE_database.split('.xlsx')[0] + '-result.xlsx')
