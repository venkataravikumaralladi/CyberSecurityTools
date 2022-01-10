# -*- coding: utf-8 -*-
"""
Created on Mon Dec 27 17:01:25 2021

@author: Venkata Ravi Kumar A

"""

# Common substitutions people used for letters to make 
# password more secure or to meeting password rules. 
# This data we can get from reconnasissance from open information.
common_subs = {
  'a' : ['@', '4'],
  'b' : ['8'],
  'e' : ['3'],
  'g' : ['6', '9'],
  'i' : ['1', '!'],
  'o' : ['0'],
  's' : ['5', '$'],
  't' : ['7', '+']
}

def gen_variations(password):
    password_variations = ['']
    
    for p in password:
        uppers = [v+p.upper() for v in password_variations]
        lowers = [v+p.lower() for v in password_variations]
        # note: here uppers and lowers are lists so we are appending lists
        vs = uppers + lowers
        if p in common_subs:
            for s in common_subs[p]:
                x = [v+s for v in password_variations]
                vs += x
        password_variations = vs
    return password_variations

if __name__ == '__main__':
    # unit test code.
    pass_variations = gen_variations('password')
    cnt = 0
    for password in pass_variations:
        cnt = cnt + 1
        print('cnt {} password {} '.format(cnt, password))
        if cnt == 10:
            break
        