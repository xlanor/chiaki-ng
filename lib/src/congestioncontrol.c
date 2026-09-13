// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <chiaki/congestioncontrol.h>

#define CONGESTION_CONTROL_INTERVAL_MS 200

static void *congestion_control_thread_func(void *user)
{
	ChiakiCongestionControl *control = user;
	uint64_t measured_received_sum = 0;
	uint64_t measured_lost_sum = 0;
	uint64_t reported_received_sum = 0;
	uint64_t reported_lost_sum = 0;
	uint64_t clean_report_ms = 0;
	unsigned int report_count = 0;
	chiaki_thread_set_affinity(CHIAKI_THREAD_NAME_CONGESTION);

	ChiakiErrorCode err = chiaki_bool_pred_cond_lock(&control->stop_cond);
	if(err != CHIAKI_ERR_SUCCESS)
		return NULL;

	while(true)
	{
		err = chiaki_bool_pred_cond_timedwait(&control->stop_cond, CONGESTION_CONTROL_INTERVAL_MS);
		if(err != CHIAKI_ERR_TIMEOUT)
			break;

		uint64_t received;
		uint64_t lost;
		chiaki_packet_stats_get(control->stats, true, &received, &lost);
		uint64_t measured_received = received;
		uint64_t measured_lost = lost;
		ChiakiTakionCongestionPacket packet = { 0 };
		uint64_t total = received + lost;
		control->packet_loss = total > 0 ? (double)lost / total : 0;
		if(control->packet_loss > control->packet_loss_max)
		{
			lost = total * control->packet_loss_max;
			received = total - lost;
		}
		packet.received = (uint16_t)received;
		packet.lost = (uint16_t)lost;
		chiaki_takion_send_congestion(control->takion, &packet);

		measured_received_sum += measured_received;
		measured_lost_sum += measured_lost;
		reported_received_sum += packet.received;
		reported_lost_sum += packet.lost;
		if(packet.lost > 0)
			clean_report_ms = 0;
		else if(packet.received > 0)
			clean_report_ms += CONGESTION_CONTROL_INTERVAL_MS;

		if(++report_count == 5)
		{
			uint64_t measured_total = measured_received_sum + measured_lost_sum;
			uint64_t reported_total = reported_received_sum + reported_lost_sum;
			double measured_loss = measured_total > 0 ? (double)measured_lost_sum / measured_total : 0;
			double reported_loss = reported_total > 0 ? (double)reported_lost_sum / reported_total : 0;
			CHIAKI_LOGD(control->takion->log,
				"Congestion feedback: measured received=%llu lost=%llu (%.2f%%), "
				"reported received=%llu lost=%llu (%.2f%%), clean=%llu ms",
				(unsigned long long)measured_received_sum,
				(unsigned long long)measured_lost_sum,
				measured_loss * 100.0,
				(unsigned long long)reported_received_sum,
				(unsigned long long)reported_lost_sum,
				reported_loss * 100.0,
				(unsigned long long)clean_report_ms);
			measured_received_sum = 0;
			measured_lost_sum = 0;
			reported_received_sum = 0;
			reported_lost_sum = 0;
			report_count = 0;
		}
	}

	chiaki_bool_pred_cond_unlock(&control->stop_cond);
	return NULL;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_congestion_control_start(ChiakiCongestionControl *control, ChiakiTakion *takion, ChiakiPacketStats *stats, double packet_loss_max)
{
	control->takion = takion;
	control->stats = stats;
	control->packet_loss_max = packet_loss_max;
	control->packet_loss = 0;

	ChiakiErrorCode err = chiaki_bool_pred_cond_init(&control->stop_cond);
	if(err != CHIAKI_ERR_SUCCESS)
		return err;

	err = chiaki_thread_create(&control->thread, congestion_control_thread_func, control);
	if(err != CHIAKI_ERR_SUCCESS)
	{
		chiaki_bool_pred_cond_fini(&control->stop_cond);
		return err;
	}

	chiaki_thread_set_name(&control->thread, "Chiaki Congestion Control");

	return CHIAKI_ERR_SUCCESS;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_congestion_control_stop(ChiakiCongestionControl *control)
{
	ChiakiErrorCode err = chiaki_bool_pred_cond_signal(&control->stop_cond);
	if(err != CHIAKI_ERR_SUCCESS)
		return err;

	err = chiaki_thread_join(&control->thread, NULL);
	if(err != CHIAKI_ERR_SUCCESS)
		return err;
	control->thread.thread = 0;

	return chiaki_bool_pred_cond_fini(&control->stop_cond);
}
