package com.authcore.modules.user;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.authcore.modules.user.UserRepository;

@Service
@RequiredArgsConstructor
public class UserStateService {

    @Autowired
    private final UserRepository userRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveUserState(User user){
        userRepository.save(user);
    }
}
