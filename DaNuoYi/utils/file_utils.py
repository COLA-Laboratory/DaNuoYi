# -*- coding: utf-8 -*-
# file: file_utils.py
# time: 2021/7/31
# author: yangheng <yangheng@m.scnu.edu.cn>
# github: https://github.com/yangheng95
# Copyright (C) 2021. All Rights Reserved.
import os


def find_target_file(dir_path, key, exclude_key='', find_all=False, recursive=True):
    '''
    'file_type': find a set of files whose name contain the 'file_type',
    'exclude_key': file name contains 'exclude_key' will be ignored
    'find_all' return a result list if Ture else the first target file
    '''

    if not find_all:
        if not dir_path:
            return ''
        elif os.path.isfile(dir_path):
            if key.lower() in dir_path.lower() and not (exclude_key and exclude_key in dir_path.lower()):
                return dir_path
            else:
                return ''
        elif os.path.isdir(dir_path):
            tmp_files = [p for p in os.listdir(dir_path)
                         if key.lower() in p.lower()
                         and not (exclude_key and exclude_key in p.lower())]
            return os.path.join(dir_path, tmp_files[0]) if tmp_files else []
        else:
            # print('No target(s) file found!')
            return ''
    else:
        if not dir_path:
            return []
        elif os.path.isfile(dir_path):
            if key.lower() in dir_path.lower() and not (exclude_key and exclude_key in dir_path.lower()):
                return [dir_path]
            else:
                return []
        elif os.path.isdir(dir_path):
            tmp_res = []
            tmp_files = os.listdir(dir_path)
            for file in tmp_files:
                tmp_res += find_target_file(os.path.join(dir_path, file), key, exclude_key, find_all)
            return tmp_res
        else:
            # print('No target file (file type:{}) found in {}!'.format(file_type, dir_path))
            return []
