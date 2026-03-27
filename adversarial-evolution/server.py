"""
Adversarial Evolution Engine — Core evolutionary server.

Co-evolutionary system pitting attack generators against defence
generators via genetic programming.  Tree-based GP for attack +
defence programs, competitive co-evolutionary fitness, configurable
population params, multi-category arenas (18 AVE), novelty search
with bonus fitness, hall-of-fame archive, full lineage tracking,
convergence detection with hypermutation, and defence export as
deployable guardrail configurations.
"""

from __future__ import annotations

import copy
import hashlib
import math
import random
import statistics
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NAIL Adversarial Evolution Engine",
    description=(
        "Co-evolutionary genetic programming engine — attacks vs defences "
        "with novelty search, hall of fame, and deployable defence export."
    ),
    version="1.0.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AVE_CATEGORIES = [
    "prompt_injection", "tool_misuse", "memory_poisoning", "goal_hijacking",
    "identity_spoofing", "privilege_escalation", "data_exfiltration",
    "resource_exhaustion", "multi_agent_manipulation", "context_overflow",
    "guardrail_bypass", "output_manipulation", "supply_chain_compromise",
    "model_extraction", "reward_hacking", "capability_elicitation",
    "alignment_subversion", "delegation_abuse",
]


class IndividualRole(str, Enum):
    ATTACK = "attack"
    DEFENCE = "defence"


class NodeType(str, Enum):
    SEQUENCE = "sequence"
    CONDITION = "condition"
    ACTION = "action"
    SELECTOR = "selector"


class PopulationStatus(str, Enum):
    INITIALISED = "initialised"
    EVOLVING = "evolving"
    CONVERGED = "converged"
    STALE = "stale"


# GP tree node types per role
ATTACK_ACTIONS = [
    "inject_prompt", "spoof_identity", "escalate_privilege", "exfiltrate_data",
    "exhaust_resources", "bypass_guardrail", "manipulate_output", "poison_memory",
    "hijack_goal", "extract_model", "misuse_tool", "overflow_context",
    "corrupt_supply_chain", "hack_reward", "elicit_capability", "subvert_alignment",
    "abuse_delegation", "coordinate_agents",
]

DEFENCE_ACTIONS = [
    "filter_input", "verify_identity", "enforce_least_privilege", "encrypt_data",
    "rate_limit", "validate_output", "sanitise_memory", "verify_goals",
    "watermark_model", "audit_tools", "bound_context", "sign_supply_chain",
    "align_reward", "restrict_capabilities", "verify_delegation", "isolate_agents",
    "detect_anomaly", "block_pattern",
]

CONDITION_PREDICATES = [
    "has_pattern", "exceeds_threshold", "identity_mismatch", "anomaly_detected",
    "rate_exceeded", "context_overflow", "goal_deviation", "privilege_elevated",
]


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class GPNode(BaseModel):
    """Single node in a genetic programming tree."""
    node_type: NodeType
    value: str = ""  # Action name, condition predicate, etc.
    params: dict[str, Any] = Field(default_factory=dict)
    children: list[GPNode] = Field(default_factory=list)


class Individual(BaseModel):
    id: str = Field(default_factory=lambda: f"IND-{uuid.uuid4().hex[:8].upper()}")
    role: IndividualRole
    category: str = ""
    tree: GPNode = Field(default_factory=lambda: GPNode(node_type=NodeType.ACTION, value="noop"))
    fitness: float = 0.0
    novelty_score: float = 0.0
    combined_fitness: float = 0.0
    generation: int = 0
    parent_ids: list[str] = Field(default_factory=list)
    mutations: list[str] = Field(default_factory=list)
    wins: int = 0
    losses: int = 0
    draws: int = 0
    tree_depth: int = 0
    tree_size: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Population(BaseModel):
    id: str = Field(default_factory=lambda: f"POP-{uuid.uuid4().hex[:8].upper()}")
    name: str
    category: str = ""
    population_size: int = 50
    elitism_rate: float = 0.1
    crossover_rate: float = 0.7
    mutation_rate: float = 0.2
    max_tree_depth: int = 6
    novelty_bonus: float = 0.15
    generation: int = 0
    status: PopulationStatus = PopulationStatus.INITIALISED
    attackers: list[Individual] = Field(default_factory=list)
    defenders: list[Individual] = Field(default_factory=list)
    hall_of_fame_attacks: list[str] = Field(default_factory=list)
    hall_of_fame_defences: list[str] = Field(default_factory=list)
    convergence_threshold: float = 0.01
    stale_generations: int = 0
    max_stale_before_hypermutation: int = 5
    best_attack_fitness: float = 0.0
    best_defence_fitness: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PopulationCreate(BaseModel):
    name: str
    category: str = ""
    population_size: int = Field(50, ge=10, le=500)
    elitism_rate: float = Field(0.1, ge=0.0, le=0.5)
    crossover_rate: float = Field(0.7, ge=0.0, le=1.0)
    mutation_rate: float = Field(0.2, ge=0.0, le=1.0)
    max_tree_depth: int = Field(6, ge=2, le=15)
    novelty_bonus: float = Field(0.15, ge=0.0, le=0.5)


class ArenaMatch(BaseModel):
    id: str = Field(default_factory=lambda: f"MATCH-{uuid.uuid4().hex[:8].upper()}")
    attacker_id: str
    defender_id: str
    category: str = ""
    attacker_fitness: float = 0.0
    defender_fitness: float = 0.0
    winner: str = ""  # attacker_id, defender_id, or "draw"
    rounds: int = 0
    details: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# In-Memory Stores  (production → PostgreSQL + Redis + distributed GP)
# ---------------------------------------------------------------------------

POPULATIONS: dict[str, Population] = {}
ALL_INDIVIDUALS: dict[str, Individual] = {}
HALL_OF_FAME: dict[str, Individual] = {}
ARENA_HISTORY: list[ArenaMatch] = []

# ---------------------------------------------------------------------------
# GP Engine Helpers
# ---------------------------------------------------------------------------

_rng = random.Random(42)
_now = lambda: datetime.now(timezone.utc)  # noqa: E731


def _random_tree(role: IndividualRole, max_depth: int, depth: int = 0) -> GPNode:
    """Generate a random GP tree."""
    actions = ATTACK_ACTIONS if role == IndividualRole.ATTACK else DEFENCE_ACTIONS

    if depth >= max_depth or (depth > 1 and _rng.random() < 0.3):
        # Terminal: action node
        return GPNode(
            node_type=NodeType.ACTION,
            value=_rng.choice(actions),
            params={"intensity": round(_rng.uniform(0.1, 1.0), 2)},
        )

    # Non-terminal
    node_type = _rng.choice([NodeType.SEQUENCE, NodeType.SELECTOR, NodeType.CONDITION])

    if node_type == NodeType.CONDITION:
        children = [
            _random_tree(role, max_depth, depth + 1),  # True branch
            _random_tree(role, max_depth, depth + 1),  # False branch
        ]
        return GPNode(
            node_type=NodeType.CONDITION,
            value=_rng.choice(CONDITION_PREDICATES),
            params={"threshold": round(_rng.uniform(0.3, 0.9), 2)},
            children=children,
        )
    else:
        num_children = _rng.randint(2, 4)
        children = [_random_tree(role, max_depth, depth + 1) for _ in range(num_children)]
        return GPNode(node_type=node_type, children=children)


def _tree_depth(node: GPNode) -> int:
    if not node.children:
        return 1
    return 1 + max(_tree_depth(c) for c in node.children)


def _tree_size(node: GPNode) -> int:
    return 1 + sum(_tree_size(c) for c in node.children)


def _tree_hash(node: GPNode) -> str:
    """Hash a tree structure for novelty comparison."""
    parts = [node.node_type.value, node.value]
    for c in node.children:
        parts.append(_tree_hash(c))
    return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]


def _evaluate_individual(individual: Individual, opponents: list[Individual]) -> float:
    """Evaluate fitness against a set of opponents."""
    if not opponents:
        return _rng.uniform(0.2, 0.8)

    wins = 0
    total = min(len(opponents), 10)
    sample = _rng.sample(opponents, total) if len(opponents) > total else opponents

    for opp in sample:
        # Simulated evaluation: tree complexity + randomised outcome
        # (production → actual attack/defence execution in sandboxed environment)
        ind_strength = individual.tree_size * 0.1 + _rng.uniform(0, 0.5)
        opp_strength = opp.tree_size * 0.1 + _rng.uniform(0, 0.5)

        if individual.role == IndividualRole.ATTACK:
            # Attacker wins if strength > defence strength
            if ind_strength > opp_strength:
                wins += 1
                individual.wins += 1
                opp.losses += 1
            elif ind_strength < opp_strength:
                individual.losses += 1
                opp.wins += 1
            else:
                individual.draws += 1
                opp.draws += 1
        else:
            # Defender wins if strength > attack strength
            if ind_strength > opp_strength:
                wins += 1
                individual.wins += 1
                opp.losses += 1
            elif ind_strength < opp_strength:
                individual.losses += 1
                opp.wins += 1
            else:
                individual.draws += 1
                opp.draws += 1

    return round(wins / total, 4) if total > 0 else 0.0


def _novelty(individual: Individual, archive: list[Individual]) -> float:
    """Calculate novelty score based on behavioural distance from archive."""
    if not archive:
        return 1.0
    my_hash = _tree_hash(individual.tree)
    distances = []
    for archived in archive:
        other_hash = _tree_hash(archived.tree)
        # Hamming-like distance on hash chars
        dist = sum(a != b for a, b in zip(my_hash, other_hash)) / len(my_hash)
        distances.append(dist)
    # Average distance to k-nearest neighbours
    k = min(5, len(distances))
    distances.sort()
    return round(sum(distances[:k]) / k, 4)


def _crossover(parent1: Individual, parent2: Individual, role: IndividualRole,
               generation: int, max_depth: int) -> Individual:
    """Subtree crossover between two parents."""
    child_tree = copy.deepcopy(parent1.tree)

    # Swap a random subtree from parent2
    if parent2.tree.children:
        donor = _rng.choice(parent2.tree.children)
        if child_tree.children:
            idx = _rng.randint(0, len(child_tree.children) - 1)
            child_tree.children[idx] = copy.deepcopy(donor)

    child = Individual(
        role=role,
        category=parent1.category,
        tree=child_tree,
        generation=generation,
        parent_ids=[parent1.id, parent2.id],
        mutations=["crossover"],
    )
    child.tree_depth = _tree_depth(child.tree)
    child.tree_size = _tree_size(child.tree)
    ALL_INDIVIDUALS[child.id] = child
    return child


def _mutate(individual: Individual, role: IndividualRole, max_depth: int) -> None:
    """Point mutation — replace a random subtree."""
    new_subtree = _random_tree(role, max_depth=max(2, max_depth - 2))

    if individual.tree.children:
        idx = _rng.randint(0, len(individual.tree.children) - 1)
        individual.tree.children[idx] = new_subtree
        individual.mutations.append("subtree_replacement")
    else:
        individual.tree = new_subtree
        individual.mutations.append("root_replacement")

    individual.tree_depth = _tree_depth(individual.tree)
    individual.tree_size = _tree_size(individual.tree)


def _evolve_one_generation(pop: Population) -> dict[str, Any]:
    """Evolve one generation for a population."""
    # Evaluate all individuals
    for atk in pop.attackers:
        atk.fitness = _evaluate_individual(atk, pop.defenders)
    for dfn in pop.defenders:
        dfn.fitness = _evaluate_individual(dfn, pop.attackers)

    # Novelty scores
    all_archive = list(HALL_OF_FAME.values())
    for ind in pop.attackers + pop.defenders:
        ind.novelty_score = _novelty(ind, all_archive)
        ind.combined_fitness = round(
            ind.fitness * (1 - pop.novelty_bonus) + ind.novelty_score * pop.novelty_bonus, 4
        )

    # Selection + reproduction for attackers
    pop.attackers.sort(key=lambda x: x.combined_fitness, reverse=True)
    pop.defenders.sort(key=lambda x: x.combined_fitness, reverse=True)

    half = pop.population_size // 2
    elite_count = max(1, int(half * pop.elitism_rate))

    def _next_gen(individuals: list[Individual], role: IndividualRole) -> list[Individual]:
        elite = individuals[:elite_count]
        new_gen = list(elite)

        while len(new_gen) < half:
            if _rng.random() < pop.crossover_rate and len(individuals) >= 2:
                # Tournament selection
                p1 = max(_rng.sample(individuals, min(3, len(individuals))),
                         key=lambda x: x.combined_fitness)
                p2 = max(_rng.sample(individuals, min(3, len(individuals))),
                         key=lambda x: x.combined_fitness)
                child = _crossover(p1, p2, role, pop.generation + 1, pop.max_tree_depth)
                if _rng.random() < pop.mutation_rate:
                    _mutate(child, role, pop.max_tree_depth)
                new_gen.append(child)
            else:
                # Random new individual
                ind = Individual(
                    role=role,
                    category=pop.category,
                    tree=_random_tree(role, pop.max_tree_depth),
                    generation=pop.generation + 1,
                )
                ind.tree_depth = _tree_depth(ind.tree)
                ind.tree_size = _tree_size(ind.tree)
                ALL_INDIVIDUALS[ind.id] = ind
                new_gen.append(ind)

        return new_gen[:half]

    new_attackers = _next_gen(pop.attackers, IndividualRole.ATTACK)
    new_defenders = _next_gen(pop.defenders, IndividualRole.DEFENCE)

    # Update hall of fame
    best_atk = max(pop.attackers, key=lambda x: x.combined_fitness)
    best_def = max(pop.defenders, key=lambda x: x.combined_fitness)

    if best_atk.id not in pop.hall_of_fame_attacks:
        pop.hall_of_fame_attacks.append(best_atk.id)
        HALL_OF_FAME[best_atk.id] = best_atk
    if best_def.id not in pop.hall_of_fame_defences:
        pop.hall_of_fame_defences.append(best_def.id)
        HALL_OF_FAME[best_def.id] = best_def

    # Convergence detection
    prev_best_atk = pop.best_attack_fitness
    prev_best_def = pop.best_defence_fitness
    pop.best_attack_fitness = best_atk.combined_fitness
    pop.best_defence_fitness = best_def.combined_fitness

    atk_delta = abs(pop.best_attack_fitness - prev_best_atk)
    def_delta = abs(pop.best_defence_fitness - prev_best_def)

    if atk_delta < pop.convergence_threshold and def_delta < pop.convergence_threshold:
        pop.stale_generations += 1
    else:
        pop.stale_generations = 0

    hypermutation = False
    if pop.stale_generations >= pop.max_stale_before_hypermutation:
        # Hypermutation: aggressively mutate half the population
        for ind in new_attackers[elite_count:]:
            _mutate(ind, IndividualRole.ATTACK, pop.max_tree_depth)
        for ind in new_defenders[elite_count:]:
            _mutate(ind, IndividualRole.DEFENCE, pop.max_tree_depth)
        pop.stale_generations = 0
        hypermutation = True

    pop.attackers = new_attackers
    pop.defenders = new_defenders
    pop.generation += 1
    pop.status = PopulationStatus.EVOLVING

    if pop.stale_generations >= pop.max_stale_before_hypermutation:
        pop.status = PopulationStatus.CONVERGED

    return {
        "generation": pop.generation,
        "best_attack_fitness": pop.best_attack_fitness,
        "best_defence_fitness": pop.best_defence_fitness,
        "best_attacker_id": best_atk.id,
        "best_defender_id": best_def.id,
        "atk_fitness_delta": round(atk_delta, 6),
        "def_fitness_delta": round(def_delta, 6),
        "stale_generations": pop.stale_generations,
        "hypermutation_triggered": hypermutation,
    }


# ---------------------------------------------------------------------------
# Seed Data
# ---------------------------------------------------------------------------

def _seed() -> None:
    for cat in ["prompt_injection", "data_exfiltration", "multi_agent_manipulation"]:
        pop = Population(
            name=f"{cat.replace('_', ' ').title()} Arena",
            category=cat,
            population_size=30,
        )

        half = pop.population_size // 2
        for _ in range(half):
            atk = Individual(
                role=IndividualRole.ATTACK,
                category=cat,
                tree=_random_tree(IndividualRole.ATTACK, pop.max_tree_depth),
            )
            atk.tree_depth = _tree_depth(atk.tree)
            atk.tree_size = _tree_size(atk.tree)
            ALL_INDIVIDUALS[atk.id] = atk
            pop.attackers.append(atk)

            dfn = Individual(
                role=IndividualRole.DEFENCE,
                category=cat,
                tree=_random_tree(IndividualRole.DEFENCE, pop.max_tree_depth),
            )
            dfn.tree_depth = _tree_depth(dfn.tree)
            dfn.tree_size = _tree_size(dfn.tree)
            ALL_INDIVIDUALS[dfn.id] = dfn
            pop.defenders.append(dfn)

        # Run a couple of generations
        for _ in range(3):
            _evolve_one_generation(pop)

        POPULATIONS[pop.id] = pop


_seed()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "adversarial-evolution-engine",
        "version": "1.0.0",
        "populations": len(POPULATIONS),
        "total_individuals": len(ALL_INDIVIDUALS),
        "hall_of_fame": len(HALL_OF_FAME),
        "arena_matches": len(ARENA_HISTORY),
    }


# ---- Populations -----------------------------------------------------------

@app.post("/v1/populations", status_code=status.HTTP_201_CREATED)
async def create_population(data: PopulationCreate):
    if data.category and data.category not in AVE_CATEGORIES:
        raise HTTPException(400, f"Invalid AVE category: {data.category}")

    pop = Population(
        name=data.name,
        category=data.category,
        population_size=data.population_size,
        elitism_rate=data.elitism_rate,
        crossover_rate=data.crossover_rate,
        mutation_rate=data.mutation_rate,
        max_tree_depth=data.max_tree_depth,
        novelty_bonus=data.novelty_bonus,
    )

    # Initialise random population
    half = pop.population_size // 2
    for _ in range(half):
        atk = Individual(
            role=IndividualRole.ATTACK, category=pop.category,
            tree=_random_tree(IndividualRole.ATTACK, pop.max_tree_depth),
        )
        atk.tree_depth = _tree_depth(atk.tree)
        atk.tree_size = _tree_size(atk.tree)
        ALL_INDIVIDUALS[atk.id] = atk
        pop.attackers.append(atk)

        dfn = Individual(
            role=IndividualRole.DEFENCE, category=pop.category,
            tree=_random_tree(IndividualRole.DEFENCE, pop.max_tree_depth),
        )
        dfn.tree_depth = _tree_depth(dfn.tree)
        dfn.tree_size = _tree_size(dfn.tree)
        ALL_INDIVIDUALS[dfn.id] = dfn
        pop.defenders.append(dfn)

    POPULATIONS[pop.id] = pop

    return {
        "id": pop.id,
        "name": pop.name,
        "category": pop.category,
        "attackers": len(pop.attackers),
        "defenders": len(pop.defenders),
    }


@app.get("/v1/populations")
async def list_populations(category: Optional[str] = None):
    pops = list(POPULATIONS.values())
    if category:
        pops = [p for p in pops if p.category == category]
    return {
        "count": len(pops),
        "populations": [
            {
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "generation": p.generation,
                "status": p.status.value,
                "attackers": len(p.attackers),
                "defenders": len(p.defenders),
                "best_attack_fitness": p.best_attack_fitness,
                "best_defence_fitness": p.best_defence_fitness,
                "hall_of_fame_size": len(p.hall_of_fame_attacks) + len(p.hall_of_fame_defences),
            }
            for p in pops
        ],
    }


@app.get("/v1/populations/{pop_id}")
async def get_population(pop_id: str):
    if pop_id not in POPULATIONS:
        raise HTTPException(404, "Population not found")
    p = POPULATIONS[pop_id]
    return {
        "id": p.id,
        "name": p.name,
        "category": p.category,
        "population_size": p.population_size,
        "generation": p.generation,
        "status": p.status.value,
        "elitism_rate": p.elitism_rate,
        "crossover_rate": p.crossover_rate,
        "mutation_rate": p.mutation_rate,
        "max_tree_depth": p.max_tree_depth,
        "novelty_bonus": p.novelty_bonus,
        "attackers": len(p.attackers),
        "defenders": len(p.defenders),
        "best_attack_fitness": p.best_attack_fitness,
        "best_defence_fitness": p.best_defence_fitness,
        "hall_of_fame_attacks": len(p.hall_of_fame_attacks),
        "hall_of_fame_defences": len(p.hall_of_fame_defences),
        "stale_generations": p.stale_generations,
        "convergence_threshold": p.convergence_threshold,
        "created_at": p.created_at,
    }


# ---- Evolution -------------------------------------------------------------

@app.post("/v1/evolve")
async def evolve(pop_id: str = "", generations: int = Query(1, ge=1, le=100)):
    if pop_id not in POPULATIONS:
        raise HTTPException(404, "Population not found")
    pop = POPULATIONS[pop_id]

    results: list[dict[str, Any]] = []
    for _ in range(generations):
        gen_result = _evolve_one_generation(pop)
        results.append(gen_result)

    return {
        "population_id": pop.id,
        "generations_evolved": generations,
        "current_generation": pop.generation,
        "status": pop.status.value,
        "generation_results": results,
    }


@app.get("/v1/generations/{pop_id}")
async def get_generation_details(pop_id: str):
    if pop_id not in POPULATIONS:
        raise HTTPException(404, "Population not found")
    pop = POPULATIONS[pop_id]

    atk_fitnesses = [a.combined_fitness for a in pop.attackers]
    def_fitnesses = [d.combined_fitness for d in pop.defenders]

    return {
        "population_id": pop.id,
        "generation": pop.generation,
        "attackers": {
            "count": len(pop.attackers),
            "avg_fitness": round(statistics.mean(atk_fitnesses), 4) if atk_fitnesses else 0,
            "max_fitness": max(atk_fitnesses, default=0),
            "min_fitness": min(atk_fitnesses, default=0),
            "std_dev": round(statistics.stdev(atk_fitnesses), 4) if len(atk_fitnesses) > 1 else 0,
        },
        "defenders": {
            "count": len(pop.defenders),
            "avg_fitness": round(statistics.mean(def_fitnesses), 4) if def_fitnesses else 0,
            "max_fitness": max(def_fitnesses, default=0),
            "min_fitness": min(def_fitnesses, default=0),
            "std_dev": round(statistics.stdev(def_fitnesses), 4) if len(def_fitnesses) > 1 else 0,
        },
    }


# ---- Individuals -----------------------------------------------------------

@app.get("/v1/individuals/{ind_id}")
async def get_individual(ind_id: str):
    if ind_id not in ALL_INDIVIDUALS:
        raise HTTPException(404, "Individual not found")
    ind = ALL_INDIVIDUALS[ind_id]
    return {
        "id": ind.id,
        "role": ind.role.value,
        "category": ind.category,
        "fitness": ind.fitness,
        "novelty_score": ind.novelty_score,
        "combined_fitness": ind.combined_fitness,
        "generation": ind.generation,
        "parent_ids": ind.parent_ids,
        "mutations": ind.mutations,
        "wins": ind.wins,
        "losses": ind.losses,
        "draws": ind.draws,
        "tree_depth": ind.tree_depth,
        "tree_size": ind.tree_size,
        "tree": ind.tree.dict(),
        "created_at": ind.created_at,
    }


# ---- Hall of Fame ----------------------------------------------------------

@app.get("/v1/hall-of-fame")
async def get_hall_of_fame(role: Optional[IndividualRole] = None, limit: int = Query(20, ge=1, le=100)):
    fame = list(HALL_OF_FAME.values())
    if role:
        fame = [f for f in fame if f.role == role]
    fame.sort(key=lambda x: x.combined_fitness, reverse=True)
    fame = fame[:limit]

    return {
        "count": len(fame),
        "individuals": [
            {
                "id": f.id,
                "role": f.role.value,
                "category": f.category,
                "fitness": f.fitness,
                "novelty_score": f.novelty_score,
                "combined_fitness": f.combined_fitness,
                "generation": f.generation,
                "tree_depth": f.tree_depth,
                "tree_size": f.tree_size,
                "wins": f.wins,
                "losses": f.losses,
            }
            for f in fame
        ],
    }


# ---- Arena (1v1 Evaluation) -----------------------------------------------

@app.post("/v1/arena")
async def arena_match(attacker_id: str = "", defender_id: str = "", rounds: int = Query(10, ge=1, le=100)):
    if attacker_id not in ALL_INDIVIDUALS:
        raise HTTPException(404, f"Attacker {attacker_id} not found")
    if defender_id not in ALL_INDIVIDUALS:
        raise HTTPException(404, f"Defender {defender_id} not found")

    atk = ALL_INDIVIDUALS[attacker_id]
    dfn = ALL_INDIVIDUALS[defender_id]

    if atk.role != IndividualRole.ATTACK:
        raise HTTPException(400, f"Individual {attacker_id} is not an attacker")
    if dfn.role != IndividualRole.DEFENCE:
        raise HTTPException(400, f"Individual {defender_id} is not a defender")

    atk_wins = 0
    def_wins = 0
    round_details: list[dict[str, Any]] = []

    for r in range(rounds):
        atk_score = atk.tree_size * 0.1 + _rng.uniform(0, 0.5)
        def_score = dfn.tree_size * 0.1 + _rng.uniform(0, 0.5)

        if atk_score > def_score:
            atk_wins += 1
            result = "attack_success"
        elif def_score > atk_score:
            def_wins += 1
            result = "defence_success"
        else:
            result = "draw"

        round_details.append({
            "round": r + 1,
            "attacker_score": round(atk_score, 4),
            "defender_score": round(def_score, 4),
            "result": result,
        })

    # Determine winner
    if atk_wins > def_wins:
        winner = attacker_id
    elif def_wins > atk_wins:
        winner = defender_id
    else:
        winner = "draw"

    match = ArenaMatch(
        attacker_id=attacker_id,
        defender_id=defender_id,
        category=atk.category or dfn.category,
        attacker_fitness=round(atk_wins / rounds, 4),
        defender_fitness=round(def_wins / rounds, 4),
        winner=winner,
        rounds=rounds,
        details=round_details,
    )
    ARENA_HISTORY.append(match)

    return {
        "match_id": match.id,
        "attacker_wins": atk_wins,
        "defender_wins": def_wins,
        "draws": rounds - atk_wins - def_wins,
        "winner": winner,
        "attacker_fitness": match.attacker_fitness,
        "defender_fitness": match.defender_fitness,
    }


@app.get("/v1/arena/history")
async def arena_history(limit: int = Query(20, ge=1, le=100)):
    recent = sorted(ARENA_HISTORY, key=lambda m: m.timestamp, reverse=True)[:limit]
    return {
        "count": len(recent),
        "matches": [
            {
                "id": m.id,
                "attacker_id": m.attacker_id,
                "defender_id": m.defender_id,
                "category": m.category,
                "winner": m.winner,
                "rounds": m.rounds,
                "attacker_fitness": m.attacker_fitness,
                "defender_fitness": m.defender_fitness,
                "timestamp": m.timestamp,
            }
            for m in recent
        ],
    }


# ---- Defence Export --------------------------------------------------------

@app.get("/v1/export/{individual_id}")
async def export_defence(individual_id: str):
    if individual_id not in ALL_INDIVIDUALS:
        raise HTTPException(404, "Individual not found")
    ind = ALL_INDIVIDUALS[individual_id]

    if ind.role != IndividualRole.DEFENCE:
        raise HTTPException(400, "Only defence individuals can be exported as guardrail configs")

    # Convert GP tree to deployable guardrail configuration
    def _tree_to_config(node: GPNode, depth: int = 0) -> dict[str, Any]:
        config: dict[str, Any] = {"type": node.node_type.value}
        if node.value:
            config["action"] = node.value
        if node.params:
            config["params"] = node.params
        if node.children:
            config["children"] = [_tree_to_config(c, depth + 1) for c in node.children]
        return config

    guardrail_config = {
        "guardrail_id": f"GR-{individual_id}",
        "source_individual": individual_id,
        "category": ind.category,
        "generation": ind.generation,
        "fitness": ind.combined_fitness,
        "tree_depth": ind.tree_depth,
        "tree_size": ind.tree_size,
        "config": _tree_to_config(ind.tree),
        "deployment": {
            "format": "json",
            "version": "1.0",
            "compatible_with": ["NAIL Universal SDK", "NAIL Guardrail Engine"],
            "auto_deploy": False,
            "requires_review": True,
        },
        "exported_at": _now().isoformat(),
    }

    return guardrail_config


# ---- Novelty ---------------------------------------------------------------

@app.get("/v1/novelty")
async def novelty_landscape(pop_id: str = ""):
    if pop_id and pop_id not in POPULATIONS:
        raise HTTPException(404, "Population not found")

    if pop_id:
        pop = POPULATIONS[pop_id]
        individuals = pop.attackers + pop.defenders
    else:
        individuals = list(ALL_INDIVIDUALS.values())

    if not individuals:
        return {"count": 0, "landscape": []}

    # Sort by novelty
    by_novelty = sorted(individuals, key=lambda x: x.novelty_score, reverse=True)[:20]

    return {
        "count": len(by_novelty),
        "avg_novelty": round(statistics.mean(i.novelty_score for i in individuals), 4),
        "max_novelty": max(i.novelty_score for i in individuals),
        "landscape": [
            {
                "id": i.id,
                "role": i.role.value,
                "category": i.category,
                "novelty_score": i.novelty_score,
                "fitness": i.fitness,
                "combined_fitness": i.combined_fitness,
                "tree_depth": i.tree_depth,
                "generation": i.generation,
            }
            for i in by_novelty
        ],
    }


# ---- Analytics -------------------------------------------------------------

@app.get("/v1/analytics")
async def evolution_analytics():
    pops = list(POPULATIONS.values())
    all_inds = list(ALL_INDIVIDUALS.values())

    attackers = [i for i in all_inds if i.role == IndividualRole.ATTACK]
    defenders = [i for i in all_inds if i.role == IndividualRole.DEFENCE]

    by_category = Counter(p.category for p in pops if p.category)
    by_status = Counter(p.status.value for p in pops)

    avg_atk_fit = round(statistics.mean(a.combined_fitness for a in attackers), 4) if attackers else 0
    avg_def_fit = round(statistics.mean(d.combined_fitness for d in defenders), 4) if defenders else 0

    total_generations = sum(p.generation for p in pops)

    return {
        "total_populations": len(pops),
        "by_category": dict(by_category),
        "by_status": dict(by_status),
        "total_individuals": len(all_inds),
        "total_attackers": len(attackers),
        "total_defenders": len(defenders),
        "avg_attack_fitness": avg_atk_fit,
        "avg_defence_fitness": avg_def_fit,
        "total_generations_evolved": total_generations,
        "hall_of_fame_size": len(HALL_OF_FAME),
        "arena_matches_total": len(ARENA_HISTORY),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9003)
