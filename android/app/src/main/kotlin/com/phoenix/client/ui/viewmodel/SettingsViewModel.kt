package com.phoenix.client.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.phoenix.client.domain.repository.ConfigRepository
import com.phoenix.client.domain.model.ClientConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val configRepository: ConfigRepository,
) : ViewModel() {

    val config: StateFlow<ClientConfig> = configRepository
        .observeConfig()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ClientConfig())

    fun setVpnMode(useVpn: Boolean) {
        viewModelScope.launch {
            configRepository.saveConfig(config.value.copy(useVpnMode = useVpn))
        }
    }
}
