# 🧠 Meta-Learning Orchestrator

**Phase 29 · Service 1 · Port 9920**

System that monitors all AI components and learns optimal configurations, hyperparameters, and strategies through continuous meta-learning across the platform.

## Capabilities

| Capability | Detail |
|---|---|
| **Component Registry** | 7 component types: `classifier`, `detector`, `recommender`, `generator`, `embedder`, `ranker`, `agent` with current config snapshot + performance baseline |
| **Config Space** | Hyperparameter definitions per component: name, type (float/int/bool/categorical), range/choices, current value, sensitivity rating 0-1 |
| **Experiment Tracking** | Meta-learning trials: config variant → performance delta, with statistical significance testing |
| **Strategy Library** | 6 optimisation strategies: `grid_search`, `random_search`, `bayesian_optimisation`, `evolutionary`, `bandit`, `transfer_learning` |
| **Performance Signals** | 8 metric types: `accuracy`, `latency_p99`, `throughput`, `false_positive_rate`, `false_negative_rate`, `resource_usage`, `drift_score`, `user_satisfaction` |
| **Meta-Model** | Learns which strategies work best for which component types; builds a strategy-component affinity matrix |
| **Auto-Tuning** | Generates recommended config updates with estimated improvement + confidence interval |
| **Transfer Learning** | Applies successful config patterns from one component to similar components |
| **Rollback Safety** | Every config change is versioned; auto-rollback if performance degrades beyond threshold |
| **Analytics** | Trials completed, improvement rate, best strategies per component type, config drift tracking |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/v1/components` | Register AI component |
| `GET` | `/v1/components` | List components with current configs |
| `GET` | `/v1/components/{cid}` | Get component detail |
| `POST` | `/v1/components/{cid}/configs` | Add hyperparameter definition |
| `POST` | `/v1/components/{cid}/signals` | Record performance signal |
| `POST` | `/v1/trials` | Run a meta-learning trial |
| `GET` | `/v1/trials` | List trials |
| `GET` | `/v1/trials/{tid}` | Get trial detail |
| `GET` | `/v1/components/{cid}/recommendations` | Get auto-tuning recommendations |
| `GET` | `/v1/strategy-affinity` | Strategy-component affinity matrix |
| `GET` | `/v1/analytics` | Meta-learning analytics |
