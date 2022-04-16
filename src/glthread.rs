#[repr(C)]
pub struct GLThread{
    pub left: *mut GLThread,
    pub right: *mut GLThread,
}

pub fn init_glthread() ->  GLThread {
    GLThread {
        left: std::ptr::null_mut(),
        right: std::ptr::null_mut() ,
    }
}

pub unsafe fn glthread_add_next(curr_glthread: *mut GLThread, new_glthread: *mut GLThread) {

    if !(*curr_glthread).right.is_null() {
        let mut tmp = (*curr_glthread).right;
        (*tmp).left = new_glthread;
        (*new_glthread).right = tmp;
    }
    (*curr_glthread).right = new_glthread;

}

pub unsafe fn glthread_add_before(curr_glthread: *mut GLThread, new_glthread: *mut GLThread) {

    if !(*curr_glthread).left.is_null() {
        let mut tmp = (*curr_glthread).left;
        (*tmp).right = new_glthread;
        (*new_glthread).left = tmp;
    }
    (*curr_glthread).left = new_glthread;
}

pub unsafe fn remove_glthread(curr_glthread: *mut GLThread) {

    if !(*curr_glthread).left.is_null() {
        (*(*curr_glthread).left).left = (*curr_glthread).right;
    }
    if !(*curr_glthread).right.is_null() {
        (*(*curr_glthread).right).left = (*curr_glthread).left;
    }
    (*curr_glthread).left = std::ptr::null_mut();
    (*curr_glthread).right = std::ptr::null_mut();
}

pub unsafe fn glthrea_add_last(base_glthread: *mut GLThread, new_glthread: *mut GLThread) {
    let mut tmp =  base_glthread;
    while !(*tmp).right.is_null() {
        tmp = (*tmp).right;
    }
    (*tmp).right = new_glthread;
}

pub unsafe fn get_glthread_list_count(base_glthread: *mut GLThread) -> usize{
    let mut count = 1;
    let mut tmp = base_glthread;
    while !tmp.is_null() {
        tmp = (*tmp).right;
        count += 1;
    }
    count
}

pub unsafe fn glthread_priority_insert(
    base_glthread: *mut GLThread,
    glthread: *mut GLThread ) {

}

